/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include <errno.h>
#include <linux/sched.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "pal.h"
#include "pal_error.h"
#include "shim_checkpoint.h"
#include "shim_context.h"
#include "shim_internal.h"
#include "shim_ipc.h"
#include "shim_lock.h"
#include "shim_table.h"
#include "shim_thread.h"
#include "shim_types.h"
#include "shim_utils.h"

void __attribute__((weak)) syscall_wrapper_after_syscalldb(void) {
    /*
     * workaround for linking.
     * syscalldb.S is excluded for libsysdb_debug.so so it fails to link
     * due to missing syscall_wrapper_after_syscalldb.
     */
}

/*
 * This Function is a wrapper around the user provided function.
 * Code flow for clone is as follows -
 * 1) User application allocates stack for child process and
 *    calls clone. The clone code sets up the user function
 *    address and the argument address on the child stack.
 * 2)we Hijack the clone call and control flows to shim_clone
 * 3)In Shim Clone we just call the DK Api to create a thread by providing a
 *   wrapper function around the user provided function
 * 4)PAL layer allocates a stack and then invokes the clone syscall
 * 5)PAL runs thread_init function on PAL allocated Stack
 * 6)thread_init calls our wrapper and gives the user provided stack
 *   address.
 * 7.In the wrapper function ,we just do the stack switch to user
 *   Provided stack and execute the user Provided function.
 */
static int clone_implementation_wrapper(struct shim_clone_args* arg) {
    // The child thread created by PAL is now running on the
    // PAL allocated stack. We need to switch the stack to use
    // the user provided stack.

    /* We acquired ownership of arg->thread from the caller, hence there is
     * no need to call get_thread. */
    struct shim_thread* my_thread = arg->thread;
    assert(my_thread);

    shim_tcb_init();
    set_cur_thread(my_thread);
    update_fs_base(arg->fs_base);
    shim_tcb_t* tcb = my_thread->shim_tcb;

    /* only now we can call LibOS/PAL functions because they require a set-up TCB;
     * do not move the below functions before shim_tcb_init/set_cur_thread()! */
    object_wait_with_retry(arg->create_event);
    DkObjectClose(arg->create_event);

    __disable_preempt(tcb); // Temporarily disable preemption, because the preemption
                            // will be re-enabled when the thread starts.

    struct debug_buf debug_buf;
    debug_setbuf(tcb, &debug_buf);

    debug("set fs_base to 0x%lx\n", tcb->context.fs_base);

    struct shim_regs regs = *arg->parent->shim_tcb->context.regs;

    /* FIXME: The below XSAVE area restore is not really correct but rather a dummy and will be
     * fixed later. Now it restores the extended state from within LibOS rather than the app. In
     * reality, XSAVE area should be part of shim_regs, and XRSTOR should happen during
     * restore_context(). */
    shim_xstate_restore(arg->xstate_extended);

    if (my_thread->set_child_tid) {
        *(my_thread->set_child_tid) = my_thread->tid;
        my_thread->set_child_tid = NULL;
    }

    void* stack = arg->stack;

    struct shim_vma_info vma_info;
    if (lookup_vma(ALLOC_ALIGN_DOWN_PTR(stack), &vma_info) < 0) {
        return -EFAULT;
    }
    my_thread->stack_top = (char*)vma_info.addr + vma_info.length;
    my_thread->stack_red = my_thread->stack = vma_info.addr;
    if (vma_info.file) {
        put_handle(vma_info.file);
    }

    /* until now we're not ready to be exposed to other thread */
    add_thread(my_thread);
    set_as_child(arg->parent, my_thread);

    /* Don't signal the initialize event until we are actually init-ed */
    DkEventSet(arg->initialize_event);

    /***** From here down, we are switching to the user-provided stack ****/

    // user_stack_addr[0] ==> user provided function address
    // user_stack_addr[1] ==> arguments to user provided function.

    debug("child swapping stack to %p return 0x%lx: %d\n", stack, shim_regs_get_ip(&regs),
          my_thread->tid);

    tcb->context.regs = &regs;
    fixup_child_context(tcb->context.regs);
    shim_context_set_sp(&tcb->context, (unsigned long)stack);

    put_thread(my_thread);

    restore_child_context_after_clone(&tcb->context);
    return 0;
}

static BEGIN_MIGRATION_DEF(fork, struct shim_thread* thread,
                           struct shim_process_ipc_info* process_ipc_info) {
    DEFINE_MIGRATE(process_ipc_info, process_ipc_info, sizeof(struct shim_process_ipc_info));
    DEFINE_MIGRATE(all_mounts, NULL, 0);
    DEFINE_MIGRATE(all_vmas, NULL, 0);
    DEFINE_MIGRATE(thread, thread, sizeof(struct shim_thread));
    DEFINE_MIGRATE(migratable, NULL, 0);
    DEFINE_MIGRATE(brk, NULL, 0);
    DEFINE_MIGRATE(loaded_libraries, NULL, 0);
#ifdef DEBUG
    DEFINE_MIGRATE(gdb_map, NULL, 0);
#endif
    DEFINE_MIGRATE(groups_info, NULL, 0);
}
END_MIGRATION_DEF(fork)

static int migrate_fork(struct shim_cp_store* store, struct shim_thread* thread,
                        struct shim_process_ipc_info* process_ipc_info, va_list ap) {
    __UNUSED(ap);
    int ret = START_MIGRATE(store, fork, thread, process_ipc_info);

    if (thread->exec) {
        put_handle(thread->exec);
        thread->exec = NULL;
    }

    return ret;
}

long shim_do_clone(unsigned long flags, unsigned long user_stack_addr, int* parent_tidptr,
                  int* child_tidptr, unsigned long tls) {
    struct shim_thread* self = get_cur_thread();
    assert(self);
    int* set_parent_tid = NULL;
    long ret = 0;

    /*
     * Currently not supported:
     * CLONE_PARENT
     * CLONE_IO
     * CLONE_PIDFD
     * CLONE_NEWNS and friends
     */
    const unsigned long supported_flags =
        CLONE_CHILD_CLEARTID |
        CLONE_CHILD_SETTID |
        CLONE_DETACHED |
        CLONE_FILES |
        CLONE_FS |
        CLONE_PARENT_SETTID |
        CLONE_PTRACE |
        CLONE_SETTLS |
        CLONE_SIGHAND |
        CLONE_SYSVSEM |
        CLONE_THREAD |
        CLONE_UNTRACED |
        CLONE_VFORK |
        CLONE_VM |
        CSIGNAL;

    if (flags & ~supported_flags) {
        debug("clone called with unsupported flags argument.\n");
        return -EINVAL;
    }

    /* CLONE_DETACHED is deprecated and ignored. */
    flags &= ~CLONE_DETACHED;

    /* These 2 flags modify ptrace behavior and can be ignored in Graphene. */
    flags &= ~(CLONE_PTRACE | CLONE_UNTRACED);

    if ((flags & CLONE_THREAD) && !(flags & CLONE_SIGHAND))
        return -EINVAL;
    if ((flags & CLONE_SIGHAND) && !(flags & CLONE_VM))
        return -EINVAL;

    /* Explicitly disallow CLONE_VM without either of CLONE_THREAD or CLONE_VFORK in Graphene. While
     * the Linux allows for such combinations, they do not happen in the wild, so they are
     * explicitly disallowed for now. */
    if (flags & CLONE_VM) {
        if (!((flags & CLONE_THREAD) || (flags & CLONE_VFORK))) {
            debug("CLONE_VM without either CLONE_THREAD or CLONE_VFORK is unsupported\n");
            return -EINVAL;
        }
    }

    if (flags & CLONE_VFORK) {
        /* Instead of trying to support Linux semantics for vfork() -- which requires adding
         * corner-cases in signal handling and syscalls -- we simply treat vfork() as fork(). We
         * assume that performance hit is negligible (Graphene has to migrate internal state anyway
         * which is slow) and apps do not rely on insane Linux-specific semantics of vfork().  */
        debug("vfork was called by the application, implemented as an alias to fork in Graphene\n");
        flags &= ~(CLONE_VFORK | CLONE_VM);
    }

    if (!(flags & CLONE_VM)) {
        /* If thread/process does not share VM we cannot handle these flags. */
        if (flags & (CLONE_FILES | CLONE_FS | CLONE_SYSVSEM)) {
            return -EINVAL;
        }
    } else {
        /* If it does share VM, we currently assume these flags are set. Supposedly erroring out
         * here would break too many applications ... */
        // TODO: either implement these flags (shouldn't be hard) or return an error
        flags |= CLONE_FS | CLONE_SYSVSEM;
    }

    if (flags & CLONE_PARENT_SETTID) {
        if (!parent_tidptr)
            return -EINVAL;
        set_parent_tid = parent_tidptr;
    }

    disable_preempt(NULL);

    struct shim_thread* thread = get_new_thread(0);
    if (!thread) {
        ret = -ENOMEM;
        goto failed;
    }

    IDTYPE tid = thread->tid;

    if (flags & CLONE_CHILD_SETTID) {
        if (!child_tidptr) {
            ret = -EINVAL;
            goto failed;
        }
        thread->set_child_tid = child_tidptr;
    }

    if (flags & CLONE_CHILD_CLEARTID)
        thread->clear_child_tid = child_tidptr;

    unsigned long fs_base = 0;
    if (flags & CLONE_SETTLS) {
        fs_base = tls_to_fs_base(tls);
    }

    if (!(flags & CLONE_VM)) {
        /* New process has its own address space - currently in Graphene that means it's just
         * another process. */
        assert(!(flags & CLONE_THREAD));

        if ((flags & CSIGNAL) != SIGCHLD) {
            debug("Currently only SIGCHLD is supported as child-death signal in clone() flags.\n");
            ret = -EINVAL;
            goto failed;
        }

        /* TODO: broken, see https://github.com/oscarlab/graphene/issues/1903
        ret = prepare_ipc_leader();
        if (ret < 0) {
            goto failed;
        }
        */

        thread->tgid = thread->tid;

        /* Associate new cpu context to the new process (its main and only thread) for migration
         * since we might need to modify some registers. */
        shim_tcb_t shim_tcb;
        /* Preemption is disabled and we are copying our own tcb, which should be ok to do,
         * even without any locks. Note this is a shallow copy, so `shim_tcb.context.regs` will be
         * shared with the parent. */
        shim_tcb = *self->shim_tcb;
        __shim_tcb_init(&shim_tcb);
        shim_tcb.tp = NULL;
        thread->shim_tcb = &shim_tcb;

        if (flags & CLONE_SETTLS) {
            shim_tcb.context.fs_base = fs_base;
        }

        unsigned long parent_stack = 0;
        if (user_stack_addr) {
            struct shim_vma_info vma_info;
            if (lookup_vma((void*)ALLOC_ALIGN_DOWN(user_stack_addr), &vma_info) < 0) {
                ret = -EFAULT;
                goto failed;
            }
            thread->stack_top = (char*)vma_info.addr + vma_info.length;
            thread->stack_red = thread->stack = vma_info.addr;
            parent_stack = shim_context_get_sp(&self->shim_tcb->context);
            shim_context_set_sp(&thread->shim_tcb->context, user_stack_addr);

            if (vma_info.file) {
                put_handle(vma_info.file);
            }
        }

        thread->is_alive = true;
        thread->in_vm    = false;
        add_thread(thread);
        set_as_child(self, thread);

        ret = create_process_and_send_checkpoint(&migrate_fork, /*exec=*/NULL, thread);

        if (parent_stack) {
            shim_context_set_sp(&self->shim_tcb->context, parent_stack);
        }

        struct shim_handle_map* handle_map = thread->handle_map;
        thread->handle_map = NULL;
        thread->shim_tcb = NULL;

        if (handle_map)
            put_handle_map(handle_map);

        if (ret < 0) {
            // FIXME: here we leak the `thread` as it's also set as `self` child. This code will
            // soon be removed, so I'm leaving this as it is.
            del_thread(thread);
            goto failed;
        }

        if (set_parent_tid)
            *set_parent_tid = tid;

        put_thread(thread);
        enable_preempt(NULL);
        return tid;
    }

    assert(flags & CLONE_THREAD);

    /* Threads do not generate signals on death, ignore it. */
    flags &= ~CSIGNAL;

    if (!(flags & CLONE_FILES)) {
        /* If CLONE_FILES is not given, the new thread should receive its own copy of the
         * descriptors table. */
        struct shim_handle_map* new_map = NULL;

        dup_handle_map(&new_map, thread->handle_map);
        set_handle_map(thread, new_map);
        put_handle_map(new_map);
    }

    /* Currently CLONE_SIGHAND is always set here, since CLONE_VM implies CLONE_THREAD (which
     * implies CLONE_SIGHAND). */
    assert(flags & CLONE_SIGHAND);

    enable_locking();

    struct shim_clone_args new_args;
    memset(&new_args, 0, sizeof(new_args));

    new_args.create_event = DkNotificationEventCreate(PAL_FALSE);
    if (!new_args.create_event) {
        ret = -PAL_ERRNO();
        goto clone_thread_failed;
    }

    new_args.initialize_event = DkNotificationEventCreate(PAL_FALSE);
    if (!new_args.initialize_event) {
        ret = -PAL_ERRNO();
        goto clone_thread_failed;
    }

    /* Increasing refcount due to copy below. Passing ownership of the new copy
     * of this pointer to the new thread (receiver of new_args). */
    get_thread(thread);
    new_args.thread  = thread;
    new_args.parent  = self;
    new_args.stack   = (void*)(user_stack_addr ?: shim_context_get_sp(&self->shim_tcb->context));
    new_args.fs_base = fs_base;

    /* FIXME: The below XSAVE area save is not really correct but rather a dummy and will be fixed
     * later. Now it saves the extended state from within LibOS rather than the app. In reality,
     * XSAVE area should be part of shim_regs, and XSAVE should happen during syscalldb().
     * Also note that we require up to 4KB of stack space for XSAVE -- this is wrong for e.g. Go
     * because its goroutines start with 2KB stack size; but we'll remove XSAVE here anyway. */
    size_t xstate_extended_size = g_shim_xsave_size + SHIM_FP_XSTATE_MAGIC2_SIZE;
    new_args.xstate_extended    = ALIGN_DOWN_PTR(new_args.stack - xstate_extended_size,
                                                 SHIM_XSTATE_ALIGN);
    shim_xstate_save(new_args.xstate_extended);

    // Invoke DkThreadCreate to spawn off a child process using the actual
    // "clone" system call. DkThreadCreate allocates a stack for the child
    // and then runs the given function on that stack However, we want our
    // child to run on the Parent allocated stack , so once the DkThreadCreate
    // returns .The parent comes back here - however, the child is Happily
    // running the function we gave to DkThreadCreate.
    PAL_HANDLE pal_handle = thread_create(clone_implementation_wrapper, &new_args);
    if (!pal_handle) {
        ret = -PAL_ERRNO();
        put_thread(new_args.thread);
        goto clone_thread_failed;
    }

    thread->pal_handle = pal_handle;
    thread->in_vm = thread->is_alive = true;

    if (set_parent_tid)
        *set_parent_tid = tid;

    DkEventSet(new_args.create_event);
    object_wait_with_retry(new_args.initialize_event);
    DkObjectClose(new_args.initialize_event);
    put_thread(thread);
    enable_preempt(NULL);
    return tid;

clone_thread_failed:
    if (new_args.create_event)
        DkObjectClose(new_args.create_event);
    if (new_args.initialize_event)
        DkObjectClose(new_args.initialize_event);
failed:
    if (thread)
        put_thread(thread);
    enable_preempt(NULL);
    return ret;
}
