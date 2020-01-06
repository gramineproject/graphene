/* Copyright (C) 2014 Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * shim_clone.c
 *
 * Implementation of system call "clone". (using "clone" as "fork" is not
 * implemented yet.)
 */

#include <shim_types.h>
#include <shim_internal.h>
#include <shim_table.h>
#include <shim_thread.h>
#include <shim_utils.h>
#include <shim_checkpoint.h>
#include <shim_profile.h>

#include <pal.h>
#include <pal_error.h>

#include <errno.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <linux/sched.h>
#include <asm/prctl.h>

void __attribute__((weak)) syscall_wrapper_after_syscalldb(void)
{
    /*
     * workaround for linking.
     * syscalldb.S is excluded for libsysdb_debug.so so it fails to link
     * due to missing syscall_wrapper_after_syscalldb.
     */
}

/*
 * See syscall_wrapper @ syscalldb.S and illegal_upcall() @ shim_signal.c
 * for details.
 * child thread can _not_ use parent stack. So return right after syscall
 * instruction as if syscall_wrapper is executed.
 */
static void fixup_child_context(struct shim_regs * regs)
{
    if (regs->rip == (unsigned long)&syscall_wrapper_after_syscalldb) {
        /*
         * we don't need to emulate stack pointer change because %rsp is
         * initialized to new child user stack passed to clone() system call.
         * See the caller of fixup_child_context().
         */
        /* regs->rsp += RED_ZONE_SIZE; */
        regs->rflags = regs->r11;
        regs->rip = regs->rcx;
    }
}

/* from **sysdeps/unix/sysv/linux/x86_64/clone.S:
   The userland implementation is:
   int clone (int (*fn)(void *arg), void *child_stack, int flags, void *arg),
   the kernel entry is:
   int clone (long flags, void *child_stack).

   The parameters are passed in register and on the stack from userland:
   rdi: fn
   rsi: child_stack
   rdx: flags
   rcx: arg
   r8d: TID field in parent
   r9d: thread pointer
   %esp+8:	TID field in child

   The kernel expects:
   rax: system call number
   rdi: flags
   rsi: child_stack
   rdx: TID field in parent
   r10: TID field in child
   r8:  thread pointer
*/

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
static int clone_implementation_wrapper(struct shim_clone_args * arg)
{
    //The child thread created by PAL is now running on the
    //PAL allocated stack. We need to switch the stack to use
    //the user provided stack.

    /* We acquired ownership of arg->thread from the caller, hence there is
     * no need to call get_thread. */
    struct shim_thread* my_thread = arg->thread;
    assert(my_thread);

    shim_tcb_init();
    set_cur_thread(my_thread);
    update_fs_base(arg->fs_base);
    shim_tcb_t * tcb = my_thread->shim_tcb;

    /* only now we can call LibOS/PAL functions because they require a set-up TCB;
     * do not move the below functions before shim_tcb_init/set_cur_thread()! */
    object_wait_with_retry(arg->create_event);
    DkObjectClose(arg->create_event);

    __disable_preempt(tcb); // Temporarily disable preemption, because the preemption
                            // will be re-enabled when the thread starts.
    debug_setbuf(tcb, true);
    debug("set fs_base to 0x%lx\n", tcb->context.fs_base);

    struct shim_regs regs = *arg->parent->shim_tcb->context.regs;
    if (my_thread->set_child_tid) {
        *(my_thread->set_child_tid) = my_thread->tid;
        my_thread->set_child_tid = NULL;
    }

    void * stack = arg->stack;

    struct shim_vma_val vma;
    lookup_vma(ALLOC_ALIGN_DOWN_PTR(stack), &vma);
    my_thread->stack_top = vma.addr + vma.length;
    my_thread->stack_red = my_thread->stack = vma.addr;

    /* until now we're not ready to be exposed to other thread */
    add_thread(my_thread);
    set_as_child(arg->parent, my_thread);

    /* Don't signal the initialize event until we are actually init-ed */
    DkEventSet(arg->initialize_event);

    /***** From here down, we are switching to the user-provided stack ****/

    //user_stack_addr[0] ==> user provided function address
    //user_stack_addr[1] ==> arguments to user provided function.

    debug("child swapping stack to %p return 0x%lx: %d\n",
          stack, regs.rip, my_thread->tid);

    tcb->context.regs = &regs;
    fixup_child_context(tcb->context.regs);
    tcb->context.regs->rsp = (unsigned long)stack;

    put_thread(my_thread);

    restore_context(&tcb->context);
    return 0;
}

int migrate_fork (struct shim_cp_store * cpstore,
                  struct shim_thread * thread,
                  struct shim_process * process, va_list ap);

/*  long int __arg0 - flags
 *  long int __arg1 - 16 bytes ( 2 words ) offset into the child stack allocated
 *                    by the parent     */

int shim_do_clone (int flags, void * user_stack_addr, int * parent_tidptr,
                   int * child_tidptr, void * tls)
{
    //The Clone Implementation in glibc has setup the child's stack
    //with the function pointer and the argument to the funciton.
    INC_PROFILE_OCCURENCE(syscall_use_ipc);
    struct shim_thread * self = get_cur_thread();
    assert(self);
    int * set_parent_tid = NULL;
    int ret = 0;

    /* special case for vfork. some runtime uses clone() for vfork */
    if (flags == (CLONE_VFORK | CLONE_VM | SIGCHLD) &&
        user_stack_addr == NULL && parent_tidptr == NULL &&
        child_tidptr == NULL && tls == NULL) {
        return shim_do_vfork();
    }

    const int supported_flags =
        CLONE_CHILD_CLEARTID |
        CLONE_CHILD_SETTID |
        CLONE_DETACHED | // Unused
        CLONE_FILES |
        CLONE_FS |
        CLONE_PARENT_SETTID |
#ifdef CLONE_PIDFD
        CLONE_PIDFD |
#endif
        CLONE_PTRACE | // Unused
        CLONE_SETTLS |
        CLONE_SIGHAND |
        CLONE_SYSVSEM |
        CLONE_THREAD |
        CLONE_VM |
        CSIGNAL;

    const int unsupported_flags = ~supported_flags;

    if (flags & unsupported_flags) {
        debug("clone called with unsupported flags argument.\n");
        return -EINVAL;
    }

    /* Explicitly disallow CLONE_VM without either of CLONE_THREAD or CLONE_VFORK on Graphene. While
     * Linux allows passing CLONE_VM without either of CLONE_THREAD or CLONE_VFORK, this usage is
     * exotic enough to not attempt a faithful emulation in Graphene. */
    if (flags & CLONE_VM)
        if (!((flags & CLONE_THREAD) || (flags & CLONE_VFORK))) {
            debug("CLONE_VM without either CLONE_THREAD or CLONE_VFORK is unsupported\n");
            return -EINVAL;
        }

    if ((flags & CLONE_THREAD) && !(flags & CLONE_SIGHAND))
        return -EINVAL;
    if ((flags & CLONE_SIGHAND) && !(flags & CLONE_VM))
        return -EINVAL;

    /* The caller may not have set the following three flags, but Graphene treats them as set to
     * simplify the implementation of clone. Only print a warning since returning an explicit error
     * code breaks many applications. */
    if (!(flags & CLONE_FS))
        debug("clone without CLONE_FS is not yet implemented\n");

    if (!(flags & CLONE_SIGHAND))
        debug("clone without CLONE_SIGHAND is not yet implemented\n");

    if (!(flags & CLONE_SYSVSEM))
        debug("clone without CLONE_SYSVSEM is not yet implemented\n");

#ifdef CLONE_PIDFD
    if (flags & CLONE_PIDFD) {
        if (flags & (CLONE_DETACHED | CLONE_PARENT_SETTID | CLONE_THREAD))
            return -EINVAL;
        if (test_user_memory(parent_tidptr, sizeof(*parent_tidptr), false))
            return -EFAULT;
        if (*parent_tidptr != 0)
            return -EINVAL;
    }
#endif

    if (flags & CLONE_PARENT_SETTID) {
        if (!parent_tidptr)
            return -EINVAL;
        set_parent_tid = parent_tidptr;
    }

    struct shim_thread * thread = get_new_thread(0);
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
        if (!tls) {
            ret = -EINVAL;
            goto failed;
        }
        fs_base = (unsigned long)tls;
    }

    if (!(flags & CLONE_THREAD))
        thread->tgid = thread->tid;

    struct shim_handle_map * handle_map = get_cur_handle_map(self);

    if (flags & CLONE_FILES) {
        set_handle_map(thread, handle_map);
    } else {
        /* if CLONE_FILES is not given, the new thread should receive
           a copy of current descriptor table */
        struct shim_handle_map * new_map = NULL;

        get_handle_map(handle_map);
        dup_handle_map(&new_map, handle_map);
        set_handle_map(thread, new_map);
        put_handle_map(handle_map);
    }

    if (!(flags & CLONE_VM)) {
        void * parent_stack = NULL;

        if (!fs_base) {
            fs_base = self->shim_tcb->context.fs_base;
        }
        /* associate cpu context to new forking thread for migration */
        shim_tcb_t shim_tcb;
        memcpy(&shim_tcb, self->shim_tcb, sizeof(shim_tcb_t));
        shim_tcb.context.fs_base = fs_base;
        thread->shim_tcb = &shim_tcb;

        if (user_stack_addr) {
            struct shim_vma_val vma;
            lookup_vma(ALLOC_ALIGN_DOWN_PTR(user_stack_addr), &vma);
            thread->stack_top = vma.addr + vma.length;
            thread->stack_red = thread->stack = vma.addr;
            parent_stack = (void *)self->shim_tcb->context.regs->rsp;
            thread->shim_tcb->context.regs->rsp = (unsigned long)user_stack_addr;
        }

        thread->is_alive = true;
        thread->in_vm = false;
        add_thread(thread);
        set_as_child(self, thread);

        ret = do_migrate_process(&migrate_fork, NULL, NULL, thread);
        thread->shim_tcb = NULL; /* cpu context of forked thread isn't
                                  * needed any more */
        if (parent_stack)
            self->shim_tcb->context.regs->rsp = (unsigned long)parent_stack;
        if (ret < 0)
            goto failed;

        lock(&thread->lock);
        handle_map = thread->handle_map;
        thread->handle_map = NULL;
        unlock(&thread->lock);

        if (handle_map)
            put_handle_map(handle_map);

        if (set_parent_tid)
            *set_parent_tid = tid;

        put_thread(thread);
        return tid;
    }

    enable_locking();

    struct shim_clone_args new_args;
    memset(&new_args, 0, sizeof(new_args));

    new_args.create_event = DkNotificationEventCreate(PAL_FALSE);
    if (!new_args.create_event) {
        ret = -PAL_ERRNO;
        goto clone_thread_failed;
    }

    new_args.initialize_event = DkNotificationEventCreate(PAL_FALSE);
    if (!new_args.initialize_event) {
        ret = -PAL_ERRNO;
        goto clone_thread_failed;
    }

    /* Increasing refcount due to copy below. Passing ownership of the new copy
     * of this pointer to the new thread (receiver of new_args). */
    get_thread(thread);
    new_args.thread    = thread;
    new_args.parent    = self;
    new_args.stack     = user_stack_addr;
    new_args.fs_base   = fs_base;

    // Invoke DkThreadCreate to spawn off a child process using the actual
    // "clone" system call. DkThreadCreate allocates a stack for the child
    // and then runs the given function on that stack However, we want our
    // child to run on the Parent allocated stack , so once the DkThreadCreate
    // returns .The parent comes back here - however, the child is Happily
    // running the function we gave to DkThreadCreate.
    PAL_HANDLE pal_handle = thread_create(clone_implementation_wrapper,
                                          &new_args);
    if (!pal_handle) {
        ret = -PAL_ERRNO;
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
    return tid;

clone_thread_failed:
    if (new_args.create_event)
        DkObjectClose(new_args.create_event);
    if (new_args.initialize_event)
        DkObjectClose(new_args.initialize_event);
failed:
    if (thread)
        put_thread(thread);
    return ret;
}
