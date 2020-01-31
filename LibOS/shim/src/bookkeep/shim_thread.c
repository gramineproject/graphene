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
 * shim_thread.c
 *
 * This file contains codes to maintain bookkeeping of threads in library OS.
 */

#include <shim_defs.h>
#include <shim_internal.h>
#include <shim_thread.h>
#include <shim_handle.h>
#include <shim_vma.h>
#include <shim_fs.h>
#include <shim_checkpoint.h>
#include <shim_utils.h>

#include <pal.h>
#include <list.h>

#include <linux/signal.h>

static IDTYPE tid_alloc_idx __attribute_migratable = 0;

static LISTP_TYPE(shim_thread) thread_list = LISTP_INIT;
DEFINE_LISTP(shim_simple_thread);
static LISTP_TYPE(shim_simple_thread) simple_thread_list = LISTP_INIT;
struct shim_lock thread_list_lock;

static IDTYPE internal_tid_alloc_idx = INTERNAL_TID_BASE;

PAL_HANDLE thread_start_event = NULL;

//#define DEBUG_REF

int init_thread (void)
{
    if (!create_lock(&thread_list_lock)) {
        return -ENOMEM;
    }

    struct shim_thread * cur_thread = get_cur_thread();
    if (cur_thread)
        return 0;

    if (!(cur_thread = get_new_thread(0)))
        return -ENOMEM;

    cur_thread->in_vm = cur_thread->is_alive = true;
    set_cur_thread(cur_thread);
    add_thread(cur_thread);
    cur_thread->pal_handle = PAL_CB(first_thread);
    return 0;
}

void dump_threads (void)
{
    struct shim_thread * tmp;

    lock(&thread_list_lock);
    LISTP_FOR_EACH_ENTRY(tmp, &thread_list, list) {
        debug("thread %d, vmid = %d, pgid = %d, ppid = %d, tgid = %d, in_vm = %d\n",
                tmp->tid, tmp->vmid, tmp->pgid, tmp->ppid, tmp->tgid, tmp->in_vm);
    }
    unlock(&thread_list_lock);
}

static struct shim_thread* __lookup_thread(IDTYPE tid) {
    assert(locked(&thread_list_lock));

    struct shim_thread* tmp;

    LISTP_FOR_EACH_ENTRY(tmp, &thread_list, list) {
        if (tmp->tid == tid) {
            get_thread(tmp);
            return tmp;
        }
    }

    return NULL;
}

struct shim_thread* lookup_thread(IDTYPE tid) {
    lock(&thread_list_lock);
    struct shim_thread* thread = __lookup_thread(tid);
    unlock(&thread_list_lock);
    return thread;
}

static IDTYPE get_pid(void) {
    IDTYPE idx;

    while (1) {
        IDTYPE old_idx = tid_alloc_idx;
        IDTYPE max = 0;
        idx = old_idx + 1;

        do {
            if ((idx = allocate_pid(idx, max)))
                break;

            tid_alloc_idx = idx;
            if (!idx) {
                if (max == old_idx)
                    break;

                max = old_idx;
            }
        } while (idx != tid_alloc_idx);

        if (idx != tid_alloc_idx)
            break;

        if (ipc_pid_lease_send(NULL) < 0)
            return 0;
    }

    tid_alloc_idx = idx;
    return idx;
}

static IDTYPE get_internal_pid (void)
{
    lock(&thread_list_lock);
    internal_tid_alloc_idx++;
    IDTYPE idx = internal_tid_alloc_idx;
    unlock(&thread_list_lock);
    assert(is_internal_tid(idx));
    return idx;
}

struct shim_thread * alloc_new_thread (void)
{
    struct shim_thread * thread = calloc(1, sizeof(struct shim_thread));
    if (!thread)
        return NULL;

    REF_SET(thread->ref_count, 1);
    INIT_LISTP(&thread->children);
    INIT_LIST_HEAD(thread, siblings);
    INIT_LISTP(&thread->exited_children);
    INIT_LIST_HEAD(thread, list);
    /* default value as sigalt stack isn't specified yet */
    thread->signal_altstack.ss_flags = SS_DISABLE;
    return thread;
}

struct shim_thread * get_new_thread (IDTYPE new_tid)
{
    if (!new_tid) {
        new_tid = get_pid();
        assert(new_tid);
    }

    struct shim_thread * thread = alloc_new_thread();
    if (!thread) {
        release_pid(new_tid);
        return NULL;
    }

    thread->signal_logs = signal_logs_alloc();
    if (!thread->signal_logs) {
        free(thread);
        release_pid(new_tid);
        return NULL;
    }


    struct shim_thread * cur_thread = get_cur_thread();
    thread->tid = new_tid;

    if (cur_thread) {
        /* The newly created thread will be in the same thread group
           (process group as well) with its parent */
        thread->pgid        = cur_thread->pgid;
        thread->ppid        = cur_thread->tgid;
        thread->tgid        = cur_thread->tgid;
        thread->uid         = cur_thread->uid;
        thread->gid         = cur_thread->gid;
        thread->euid        = cur_thread->euid;
        thread->egid        = cur_thread->egid;
        thread->parent      = cur_thread;
        thread->stack       = cur_thread->stack;
        thread->stack_top   = cur_thread->stack_top;
        thread->stack_red   = cur_thread->stack_red;
        thread->cwd         = cur_thread->cwd;
        thread->root        = cur_thread->root;
        thread->umask       = cur_thread->umask;
        thread->exec        = cur_thread->exec;
        get_handle(cur_thread->exec);

        for (int i = 0 ; i < NUM_SIGS ; i++) {
            if (!cur_thread->signal_handles[i].action)
                continue;

            thread->signal_handles[i].action =
                    malloc_copy(cur_thread->signal_handles[i].action,
                                sizeof(*thread->signal_handles[i].action));
        }

        memcpy(&thread->signal_mask, &cur_thread->signal_mask,
               sizeof(sigset_t));

        get_dentry(cur_thread->cwd);
        get_dentry(cur_thread->root);

        struct shim_handle_map * map = get_cur_handle_map(cur_thread);
        assert(map);
        set_handle_map(thread, map);
    } else {
        /* default pid and pgid equals to tid */
        thread->ppid = thread->pgid = thread->tgid = new_tid;
        /* This case should fall back to the global root of the file system.
         */
        path_lookupat(NULL, "/", 0, &thread->root, NULL);
        char dir_cfg[CONFIG_MAX];
        if (root_config &&
            get_config(root_config, "fs.start_dir", dir_cfg, sizeof(dir_cfg)) > 0) {
            path_lookupat(NULL, dir_cfg, 0, &thread->cwd, NULL);
        } else if (thread->root) {
            get_dentry(thread->root);
            thread->cwd = thread->root;
        }
    }

    if (!create_lock(&thread->lock)) {
        goto out_error;
    }

    thread->vmid = cur_process.vmid;
    thread->scheduler_event = DkNotificationEventCreate(PAL_TRUE);
    thread->exit_event = DkNotificationEventCreate(PAL_FALSE);
    thread->child_exit_event = DkNotificationEventCreate(PAL_FALSE);
    return thread;

out_error:
    signal_logs_free(thread->signal_logs);
    if (thread->handle_map) {
        put_handle_map(thread->handle_map);
    }
    if (thread->root) {
        put_dentry(thread->root);
    }
    if (thread->cwd) {
        put_dentry(thread->cwd);
    }
    for (int i = 0; i < NUM_SIGS; i++) {
        free(thread->signal_handles[i].action);
    }
    if (thread->exec) {
        put_handle(thread->exec);
    }
    free(thread);
    return NULL;
}

struct shim_thread * get_new_internal_thread (void)
{
    IDTYPE new_tid = get_internal_pid();
    assert(new_tid);

    struct shim_thread * thread = alloc_new_thread();
    if (!thread)
        return NULL;

    thread->vmid  = cur_process.vmid;
    thread->tid   = new_tid;
    thread->in_vm = thread->is_alive = true;
    if (!create_lock(&thread->lock)) {
        free(thread);
        return NULL;
    }
    thread->exit_event = DkNotificationEventCreate(PAL_FALSE);
    return thread;
}

struct shim_simple_thread * __lookup_simple_thread (IDTYPE tid)
{
    assert(locked(&thread_list_lock));

    struct shim_simple_thread * tmp;

    LISTP_FOR_EACH_ENTRY(tmp, &simple_thread_list, list) {
        if (tmp->tid == tid) {
            get_simple_thread(tmp);
            return tmp;
        }
    }

    return NULL;
}

struct shim_simple_thread * lookup_simple_thread (IDTYPE tid)
{
    lock(&thread_list_lock);
    struct shim_simple_thread * thread = __lookup_simple_thread(tid);
    unlock(&thread_list_lock);
    return thread;
}

struct shim_simple_thread * get_new_simple_thread (void)
{
    struct shim_simple_thread * thread =
                    malloc(sizeof(struct shim_simple_thread));

    if (!thread)
        return NULL;

    memset(thread, 0, sizeof(struct shim_simple_thread));

    INIT_LIST_HEAD(thread, list);

    if (!create_lock(&thread->lock)) {
        free(thread);
        return NULL;
    }
    thread->exit_event = DkNotificationEventCreate(PAL_FALSE);

    return thread;
}

void get_thread (struct shim_thread * thread)
{
#ifdef DEBUG_REF
    int ref_count = REF_INC(thread->ref_count);

    debug("get_thread %p(%d) (ref_count = %d)\n", thread, thread->tid,
          ref_count);
#else
    REF_INC(thread->ref_count);
#endif
}

void put_thread (struct shim_thread * thread)
{
    int ref_count = REF_DEC(thread->ref_count);

#ifdef DEBUG_REF
    debug("put_thread %p(%d) (ref_count = %d)\n", thread, thread->tid,
          ref_count);
#endif

    if (!ref_count) {
        if (thread->exec)
            put_handle(thread->exec);

        if (!is_internal(thread))
            release_pid(thread->tid);

        if (thread->pal_handle &&
            thread->pal_handle != PAL_CB(first_thread))
            DkObjectClose(thread->pal_handle);

        if (thread->scheduler_event)
            DkObjectClose(thread->scheduler_event);
        if (thread->exit_event)
            DkObjectClose(thread->exit_event);
        if (thread->child_exit_event)
            DkObjectClose(thread->child_exit_event);
        if (lock_created(&thread->lock)) {
            destroy_lock(&thread->lock);
        }

        signal_logs_free(thread->signal_logs);
        free(thread);
    }
}

void get_simple_thread (struct shim_simple_thread * thread)
{
    REF_INC(thread->ref_count);
}

static void __put_simple_thread(struct shim_simple_thread* thread) {
    assert(locked(&thread_list_lock));

    int ref_count = REF_DEC(thread->ref_count);

    if (!ref_count) {
        /* Simple threads always live on the simple thread list */
        LISTP_DEL(thread, &simple_thread_list, list);
        if (thread->exit_event)
            DkObjectClose(thread->exit_event);
        destroy_lock(&thread->lock);
        free(thread);
    }
}

void put_simple_thread(struct shim_simple_thread* thread) {
    lock(&thread_list_lock);
    __put_simple_thread(thread);
    unlock(&thread_list_lock);
}

void set_as_child (struct shim_thread * parent,
                   struct shim_thread * child)
{
    if (!parent)
        parent = get_cur_thread();

    get_thread(parent);
    get_thread(child);

    lock(&child->lock);
    child->ppid = parent->tid;
    child->parent = parent;

    lock(&parent->lock);
    LISTP_ADD_TAIL(child, &parent->children, siblings);
    unlock(&parent->lock);

    unlock(&child->lock);
}

void add_thread (struct shim_thread * thread)
{
    if (is_internal(thread) || !LIST_EMPTY(thread, list))
        return;

    struct shim_thread * tmp, * prev = NULL;
    lock(&thread_list_lock);

    /* keep it sorted */
    LISTP_FOR_EACH_ENTRY_REVERSE(tmp, &thread_list, list) {
        if (tmp->tid == thread->tid) {
            unlock(&thread_list_lock);
            return;
        }
        if (tmp->tid < thread->tid) {
            prev = tmp;
            break;
        }
    }

    get_thread(thread);
    LISTP_ADD_AFTER(thread, prev, &thread_list, list);
    unlock(&thread_list_lock);
}

void del_thread (struct shim_thread * thread)
{
    debug("del_thread(%p, %d, %ld)\n", thread, thread ? (int) thread->tid : -1,
          atomic_read(&thread->ref_count));

    if (is_internal(thread) || LIST_EMPTY(thread, list)) {
        debug("del_thread: internal\n");
        return;
    }

    lock(&thread_list_lock);
    /* thread->list goes on the thread_list */
    LISTP_DEL_INIT(thread, &thread_list, list);
    unlock(&thread_list_lock);
    put_thread(thread);
}

void add_simple_thread (struct shim_simple_thread * thread)
{
    if (!LIST_EMPTY(thread, list))
        return;

    struct shim_simple_thread * tmp, * prev = NULL;
    lock(&thread_list_lock);

    /* keep it sorted */
    LISTP_FOR_EACH_ENTRY_REVERSE(tmp, &simple_thread_list, list) {
        if (tmp->tid == thread->tid) {
            unlock(&thread_list_lock);
            return;
        }
        if (tmp->tid < thread->tid) {
            prev = tmp;
            break;
        }
    }

    get_simple_thread(thread);
    LISTP_ADD_AFTER(thread, prev, &simple_thread_list, list);
    unlock(&thread_list_lock);
}

void del_simple_thread (struct shim_simple_thread * thread)
{
    if (LIST_EMPTY(thread, list))
        return;

    lock(&thread_list_lock);
    LISTP_DEL_INIT(thread, &simple_thread_list, list);
    __put_simple_thread(thread);
    unlock(&thread_list_lock);
}

static int _check_last_thread(struct shim_thread* self) {
    assert(locked(&thread_list_lock));

    IDTYPE self_tid = self ? self->tid : 0;

    struct shim_thread* thread;
    LISTP_FOR_EACH_ENTRY(thread, &thread_list, list) {
        if (thread->tid && thread->tid != self_tid && thread->in_vm && thread->is_alive) {
            return thread->tid;
        }
    }
    return 0;
}

/* Checks for any alive threads apart from thread self. Returns tid of the first found alive thread
 * or 0 if there are no alive threads. self can be NULL, then all threads are checked. */
int check_last_thread(struct shim_thread* self) {
    lock(&thread_list_lock);
    int alive_thread_tid = _check_last_thread(self);
    unlock(&thread_list_lock);
    return alive_thread_tid;
}

/* This function is called by Async Helper thread to wait on thread->clear_child_tid_pal to be
 * zeroed (PAL does it when thread finally exits). Since it is a callback to Async Helper thread,
 * this function must follow the `void (*callback) (IDTYPE caller, void* arg)` signature. */
void cleanup_thread(IDTYPE caller, void* arg) {
    __UNUSED(caller);

    struct shim_thread* thread = (struct shim_thread*)arg;
    assert(thread);

    int exit_code = thread->term_signal ? : thread->exit_code;

    /* wait on clear_child_tid_pal; this signals that PAL layer exited child thread */
    while (__atomic_load_n(&thread->clear_child_tid_pal, __ATOMIC_RELAXED) != 0) {
        __asm__ volatile ("pause");
    }

    /* notify parent if any */
    release_clear_child_tid(thread->clear_child_tid);

    /* clean up the thread itself */
    lock(&thread_list_lock);
    thread->is_alive = false;
    LISTP_DEL_INIT(thread, &thread_list, list);

    put_thread(thread);

    if (!_check_last_thread(NULL)) {
        /* corner case when all application threads exited via exit(), only Async helper
         * and IPC helper threads are left at this point so simply exit process (recall
         * that typically processes exit via exit_group()) */
        unlock(&thread_list_lock);
        shim_clean_and_exit(exit_code);
    }

    unlock(&thread_list_lock);
}

int walk_thread_list (int (*callback) (struct shim_thread *, void *, bool *),
                      void * arg)
{
    struct shim_thread * tmp, * n;
    bool srched = false;
    int ret;
    IDTYPE min_tid = 0;

relock:
    lock(&thread_list_lock);

    debug("walk_thread_list(callback=%p)\n", callback);

    LISTP_FOR_EACH_ENTRY_SAFE(tmp, n, &thread_list, list) {
        if (tmp->tid <= min_tid)
            continue;

        bool unlocked = false;
        ret = (*callback) (tmp, arg, &unlocked);
        if (ret < 0 && ret != -ESRCH) {
            if (unlocked)
                goto out;
            else
                goto out_locked;
        }
        if (ret > 0)
            srched = true;
        if (unlocked) {
            min_tid = tmp->tid;
            goto relock;
        }
    }

    ret = srched ? 0 : -ESRCH;
out_locked:
    unlock(&thread_list_lock);
out:
    return ret;
}

int walk_simple_thread_list (int (*callback) (struct shim_simple_thread *,
                                              void *, bool *),
                             void * arg)
{
    struct shim_simple_thread * tmp, * n;
    bool srched = false;
    int ret;
    IDTYPE min_tid = 0;

relock:
    lock(&thread_list_lock);

    LISTP_FOR_EACH_ENTRY_SAFE(tmp, n, &simple_thread_list, list) {
        if (tmp->tid <= min_tid)
            continue;
        bool unlocked = false;
        ret = (*callback) (tmp, arg, &unlocked);
        if (ret < 0 && ret != -ESRCH) {
            if (unlocked)
                goto out;
            else
                goto out_locked;
        }
        if (ret > 0)
            srched = true;
        if (unlocked) {
            min_tid = tmp->tid;
            goto relock;
        }
    }

    ret = srched ? 0 : -ESRCH;
out_locked:
    unlock(&thread_list_lock);
out:
    return ret;
}

#ifndef ALIAS_VFORK_AS_FORK
void switch_dummy_thread (struct shim_thread * thread)
{
    struct shim_thread * real_thread = thread->dummy;
    IDTYPE child = thread->tid;

    assert(thread->frameptr);
    assert(real_thread->stack);
    assert(real_thread->stack_top > real_thread->stack);

    memcpy(thread->frameptr, real_thread->stack,
           real_thread->stack_top - real_thread->stack);

    real_thread->stack     = thread->stack;
    real_thread->stack_top = thread->stack_top;
    real_thread->frameptr  = thread->frameptr;

    DkSegmentRegister(PAL_SEGMENT_FS, real_thread->tcb);
    set_cur_thread(real_thread);
    debug("set tcb to %p\n", real_thread->tcb);

    debug("jump to the stack %p\n", real_thread->frameptr);
    debug("shim_vfork success (returning %d)\n", child);

    /* jump onto old stack
       we actually pop rbp as rsp, and later we will call 'ret' */
    __asm__ volatile("movq %0, %%rbp\r\n"
                     "leaveq\r\n"
                     "retq\r\n" :
                     : "g"(real_thread->frameptr),
                       "a"(child)
                     : "memory");
}
#endif

BEGIN_CP_FUNC(thread)
{
    __UNUSED(size);
    assert(size == sizeof(struct shim_thread));

    struct shim_thread * thread = (struct shim_thread *) obj;
    struct shim_thread * new_thread = NULL;

    ptr_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off = ADD_CP_OFFSET(sizeof(struct shim_thread));
        ADD_TO_CP_MAP(obj, off);
        new_thread = (struct shim_thread *) (base + off);
        memcpy(new_thread, thread, sizeof(struct shim_thread));

        INIT_LISTP(&new_thread->children);
        INIT_LIST_HEAD(new_thread, siblings);
        INIT_LISTP(&new_thread->exited_children);
        INIT_LIST_HEAD(new_thread, list);

        new_thread->in_vm  = false;
        new_thread->parent = NULL;
#ifndef ALIAS_VFORK_AS_FORK
        new_thread->dummy  = NULL;
#endif
        new_thread->handle_map = NULL;
        new_thread->root   = NULL;
        new_thread->cwd    = NULL;
        new_thread->signal_logs = NULL;
        new_thread->robust_list = NULL;
        REF_SET(new_thread->ref_count, 0);

        for (int i = 0 ; i < NUM_SIGS ; i++)
            if (thread->signal_handles[i].action) {
                ptr_t soff = ADD_CP_OFFSET(sizeof(struct __kernel_sigaction));
                new_thread->signal_handles[i].action
                        = (struct __kernel_sigaction *) (base + soff);
                memcpy(new_thread->signal_handles[i].action,
                       thread->signal_handles[i].action,
                       sizeof(struct __kernel_sigaction));
            }

        DO_CP_MEMBER(handle, thread, new_thread, exec);
        DO_CP_MEMBER(handle_map, thread, new_thread, handle_map);
        DO_CP_MEMBER(dentry, thread, new_thread, root);
        DO_CP_MEMBER(dentry, thread, new_thread, cwd);
        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_thread = (struct shim_thread *) (base + off);
    }

    if (objp)
        *objp = (void *) new_thread;
}
END_CP_FUNC(thread)

BEGIN_RS_FUNC(thread)
{
    struct shim_thread * thread = (void *) (base + GET_CP_FUNC_ENTRY());
    __UNUSED(offset);

    CP_REBASE(thread->children);
    CP_REBASE(thread->siblings);
    CP_REBASE(thread->exited_children);
    CP_REBASE(thread->list);
    CP_REBASE(thread->exec);
    CP_REBASE(thread->handle_map);
    CP_REBASE(thread->root);
    CP_REBASE(thread->cwd);
    CP_REBASE(thread->signal_handles);

    if (!create_lock(&thread->lock)) {
        return -ENOMEM;
    }
    thread->scheduler_event = DkNotificationEventCreate(PAL_TRUE);
    thread->exit_event = DkNotificationEventCreate(PAL_FALSE);
    thread->child_exit_event = DkNotificationEventCreate(PAL_FALSE);

    add_thread(thread);

    if (thread->exec)
        get_handle(thread->exec);

    if (thread->handle_map)
        get_handle_map(thread->handle_map);

    if (thread->root)
        get_dentry(thread->root);

    if (thread->cwd)
        get_dentry(thread->cwd);

    DEBUG_RS("tid=%d,tgid=%d,parent=%d,stack=%p,frameptr=%p,tcb=%p,shim_tcb=%p",
             thread->tid, thread->tgid,
             thread->parent ? thread->parent->tid : thread->tid,
             thread->stack, thread->frameptr, thread->tcb, thread->shim_tcb);
}
END_RS_FUNC(thread)

BEGIN_CP_FUNC(running_thread)
{
    __UNUSED(size);
    __UNUSED(objp);
    assert(size == sizeof(struct shim_thread));

    struct shim_thread * thread = (struct shim_thread *) obj;
    struct shim_thread * new_thread = NULL;

    DO_CP(thread, thread, &new_thread);
    ADD_CP_FUNC_ENTRY((ptr_t) new_thread - base);

    if (thread->shim_tcb) {
        ptr_t toff = ADD_CP_OFFSET(sizeof(shim_tcb_t));
        new_thread->shim_tcb = (void *)(base + toff);
        struct shim_tcb* new_tcb = new_thread->shim_tcb;
        memcpy(new_tcb, thread->shim_tcb, sizeof(*new_tcb));
        /* don't export stale pointers */
        new_tcb->self = NULL;
        new_tcb->tp = NULL;
        new_tcb->context.next = NULL;
        new_tcb->debug_buf = NULL;
    }
}
END_CP_FUNC(running_thread)

static int resume_wrapper (void * param)
{
    struct shim_thread * thread = (struct shim_thread *) param;
    assert(thread);

    /* initialize the current shim_tcb_t (= shim_get_tcb())
       based on saved thread->shim_tcb */
    shim_tcb_init();
    shim_tcb_t* saved_tcb = thread->shim_tcb;
    assert(saved_tcb->context.regs && saved_tcb->context.regs->rsp);
    set_cur_thread(thread);
    unsigned long fs_base = saved_tcb->context.fs_base;
    assert(fs_base);
    update_fs_base(fs_base);

    thread->in_vm = thread->is_alive = true;

    shim_tcb_t* tcb = shim_get_tcb();
    tcb->context.regs = saved_tcb->context.regs;
    tcb->context.enter_time = saved_tcb->context.enter_time;
    tcb->context.preempt = saved_tcb->context.preempt;
    debug_setbuf(tcb, false);
    debug("set fs_base to 0x%lx\n", fs_base);

    object_wait_with_retry(thread_start_event);

    restore_context(&tcb->context);
    return 0;
}

BEGIN_RS_FUNC(running_thread)
{
    __UNUSED(offset);
    struct shim_thread * thread = (void *) (base + GET_CP_FUNC_ENTRY());
    struct shim_thread * cur_thread = get_cur_thread();
    thread->in_vm = true;

    thread->vmid = cur_process.vmid;

    if (thread->shim_tcb)
        CP_REBASE(thread->shim_tcb);

    if (thread->set_child_tid) {
        /* CLONE_CHILD_SETTID */
        *thread->set_child_tid = thread->tid;
        thread->set_child_tid = NULL;
    }

    thread->signal_logs = signal_logs_alloc();
    if (!thread->signal_logs)
        return -ENOMEM;

    if (cur_thread) {
        PAL_HANDLE handle = DkThreadCreate(resume_wrapper, thread);
        if (!thread)
            return -PAL_ERRNO;

        thread->pal_handle = handle;
    } else {
        shim_tcb_t* saved_tcb = thread->shim_tcb;
        if (saved_tcb) {
            /* fork case */
            shim_tcb_t* tcb = shim_get_tcb();
            memcpy(tcb, saved_tcb, sizeof(*tcb));
            __shim_tcb_init(tcb);
            set_cur_thread(thread);

            assert(tcb->context.regs && tcb->context.regs->rsp);
            update_fs_base(tcb->context.fs_base);
            /* Temporarily disable preemption until the thread resumes. */
            __disable_preempt(tcb);
            debug_setbuf(tcb, false);
            debug("after resume, set tcb to 0x%lx\n", tcb->context.fs_base);
        } else {
            /*
             * In execve case, the following holds:
             * stack = NULL
             * stack_top = NULL
             * frameptr = NULL
             * tcb = NULL
             * shim_tcb = NULL
             * in_vm = false
             */
            set_cur_thread(thread);
            debug_setbuf(thread->shim_tcb, false);
        }

        thread->in_vm = thread->is_alive = true;
        thread->pal_handle = PAL_CB(first_thread);
    }

    DEBUG_RS("tid=%d", thread->tid);
}
END_RS_FUNC(running_thread)

BEGIN_CP_FUNC(all_running_threads)
{
    __UNUSED(obj);
    __UNUSED(size);
    __UNUSED(objp);
    struct shim_thread * thread;
    lock(&thread_list_lock);

    LISTP_FOR_EACH_ENTRY(thread, &thread_list, list) {
        if (!thread->in_vm || !thread->is_alive)
            continue;

        DO_CP(running_thread, thread, NULL);
        DO_CP(handle_map, thread->handle_map, NULL);
    }

    unlock(&thread_list_lock);
}
END_CP_FUNC_NO_RS(all_running_threads)
