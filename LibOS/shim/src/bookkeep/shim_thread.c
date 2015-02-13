/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2014 OSCAR lab, Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * shim_thread.c
 *
 * This file contains codes to maintain bookkeeping of threads in library OS.
 */

#include <shim_internal.h>
#include <shim_thread.h>
#include <shim_handle.h>
#include <shim_vma.h>
#include <shim_fs.h>
#include <shim_checkpoint.h>

#include <pal.h>

#include <linux_list.h>

#define THREAD_MGR_ALLOC    4

static LOCKTYPE thread_mgr_lock;

#define system_lock()   lock(thread_mgr_lock)
#define system_unlock() unlock(thread_mgr_lock)
#define PAGE_SIZE       allocsize

#define OBJ_TYPE struct shim_thread
#include <memmgr.h>

static MEM_MGR thread_mgr = NULL;

static IDTYPE tid_alloc_idx __attribute_migratable = 0;

static LIST_HEAD(thread_list);
static LIST_HEAD(simple_thread_list);
LOCKTYPE thread_list_lock;

static IDTYPE internal_tid_alloc_idx = INTERNAL_TID_BASE;

PAL_HANDLE thread_start_event = NULL;

//#define DEBUG_REF

int init_thread (void)
{
    create_lock(thread_list_lock);
    create_lock(thread_mgr_lock);

    thread_mgr = create_mem_mgr(init_align_up(THREAD_MGR_ALLOC));
    if (!thread_mgr)
        return -ENOMEM;

    struct shim_thread * cur_thread = get_cur_thread();

    if (cur_thread)
        return 0;

    if (!(cur_thread = get_new_thread(0)))
        return -ENOMEM;

    cur_thread->in_vm = cur_thread->is_alive = true;
    get_thread(cur_thread);
    set_cur_thread(cur_thread);
    add_thread(cur_thread);
    cur_thread->pal_handle = PAL_CB(first_thread);
    return 0;
}

struct shim_thread * __lookup_thread (IDTYPE tid)
{
    struct shim_thread * tmp;

    list_for_each_entry(tmp, &thread_list, list)
        if (tmp->tid == tid) {
            get_thread(tmp);
            return tmp;
        }

    return NULL;
}

struct shim_thread * lookup_thread (IDTYPE tid)
{
    lock(thread_list_lock);
    struct shim_thread * thread = __lookup_thread(tid);
    unlock(thread_list_lock);
    return thread;
}

struct shim_thread * __get_cur_thread (void)
{
    return SHIM_THREAD_SELF();
}

shim_tcb_t * __get_cur_tcb (void)
{
    return SHIM_GET_TLS();
}

static IDTYPE get_pid (void)
{
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
    lock(thread_list_lock);
    internal_tid_alloc_idx++;
    IDTYPE idx = internal_tid_alloc_idx;
    unlock(thread_list_lock);
    return idx;
}

static inline int init_mem_mgr (void)
{
    if (thread_mgr)
        return 0;

    MEM_MGR mgr = create_mem_mgr(init_align_up(THREAD_MGR_ALLOC));
    MEM_MGR old_mgr = NULL;

    lock(thread_mgr_lock);

    if (mgr) {
        if (thread_mgr) {
            old_mgr = mgr;
            mgr = thread_mgr;
        } else {
            thread_mgr = mgr;
        }
    }

    unlock(thread_mgr_lock);

    if (old_mgr)
        destroy_mem_mgr(old_mgr);

    return mgr ? 0 : -ENOMEM;
}

struct shim_thread * alloc_new_thread (void)
{
    struct shim_thread * thread =
            get_mem_obj_from_mgr_enlarge(thread_mgr,
                                         size_align_up(THREAD_MGR_ALLOC));
    if (!thread)
        return NULL;

    memset(thread, 0, sizeof(struct shim_thread));
    REF_SET(thread->ref_count, 1);
    INIT_LIST_HEAD(&thread->children);
    INIT_LIST_HEAD(&thread->siblings);
    INIT_LIST_HEAD(&thread->exited_children);
    INIT_LIST_HEAD(&thread->list);
    return thread;
}

struct shim_thread * get_new_thread (IDTYPE new_tid)
{
    if (init_mem_mgr() < 0)
        return NULL;

    if (!new_tid) {
        new_tid = get_pid();
        assert(new_tid);
    }

    struct shim_thread * thread = alloc_new_thread();
    if (!thread)
        return NULL;

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
                    remalloc(cur_thread->signal_handles[i].action,
                             sizeof(struct shim_signal_handle));
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
        path_lookupat(NULL, "/", 0, &thread->root);
        char dir_cfg[CONFIG_MAX];
        if (root_config &&
            get_config(root_config, "fs.start_dir", dir_cfg, CONFIG_MAX) > 0) {
            path_lookupat(NULL, dir_cfg, 0, &thread->cwd);
        } else if (thread->root) {
            get_dentry(thread->root);
            thread->cwd = thread->root;
        }
    }

    thread->vmid = cur_process.vmid;
    create_lock(thread->lock);
    thread->scheduler_event = DkNotificationEventCreate(1);
    thread->exit_event = DkNotificationEventCreate(0);
    thread->child_exit_event = DkNotificationEventCreate(0);
    return thread;
}

struct shim_thread * get_new_internal_thread (void)
{
    if (init_mem_mgr() < 0)
        return NULL;

    IDTYPE new_tid = get_internal_pid();
    assert(new_tid);

    struct shim_thread * thread = alloc_new_thread();
    if (!thread)
        return NULL;

    thread->vmid  = cur_process.vmid;
    thread->tid   = new_tid;
    thread->in_vm = thread->is_alive = true;
    create_lock(thread->lock);
    thread->exit_event = DkNotificationEventCreate(0);
    return thread;
}

struct shim_simple_thread * __lookup_simple_thread (IDTYPE tid)
{
    struct shim_simple_thread * tmp;

    list_for_each_entry(tmp, &simple_thread_list, list)
        if (tmp->tid == tid) {
            get_simple_thread(tmp);
            return tmp;
        }

    return NULL;
}

struct shim_simple_thread * lookup_simple_thread (IDTYPE tid)
{
    lock(thread_list_lock);
    struct shim_simple_thread * thread = __lookup_simple_thread(tid);
    unlock(thread_list_lock);
    return thread;
}

struct shim_simple_thread * get_new_simple_thread (void)
{
    struct shim_simple_thread * thread =
                    malloc(sizeof(struct shim_simple_thread));

    if (!thread)
        return NULL;

    memset(thread, 0, sizeof(struct shim_simple_thread));

    INIT_LIST_HEAD(&thread->list);

    create_lock(thread->lock);
    thread->exit_event = DkNotificationEventCreate(0);

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
    debug("put thread %p(%d) (ref_count = %d)\n", thread, thread->tid,
          ref_count);
#endif

    if (!ref_count) {
       if (thread->exec)
            put_handle(thread->exec);

        if (!IS_INTERNAL(thread))
            release_pid(thread->tid);

        if (MEMORY_MIGRATED(thread))
            memset(thread, 0, sizeof(struct shim_thread));
        else
            free_mem_obj_to_mgr(thread_mgr, thread);
    }
}

void get_simple_thread (struct shim_simple_thread * thread)
{
    REF_INC(thread->ref_count);
}

void put_simple_thread (struct shim_simple_thread * thread)
{
    int ref_count = REF_DEC(thread->ref_count);

    if (!ref_count) {
        list_del(&thread->list);
        free(thread);
    }
}

void set_as_child (struct shim_thread * parent,
                   struct shim_thread * child)
{
    if (!parent)
        parent = get_cur_thread();

    get_thread(parent);
    get_thread(child);

    lock(child->lock);
    child->ppid = parent->tid;
    child->parent = parent;

    lock(parent->lock);
    list_add_tail(&child->siblings, &parent->children);
    unlock(parent->lock);

    unlock(child->lock);
}

void add_thread (struct shim_thread * thread)
{
    if (IS_INTERNAL(thread) || !list_empty(&thread->list))
        return;

    struct shim_thread * tmp, * prev = NULL;
    lock(thread_list_lock);

    /* keep it sorted */
    list_for_each_entry_reverse(tmp, &thread_list, list) {
        if (tmp->tid == thread->tid) {
            unlock(thread_list_lock);
            return;
        }
        if (tmp->tid < thread->tid) {
            prev = tmp;
            break;
        }
    }

    get_thread(thread);
    list_add(&thread->list, prev ? &prev->list : &thread_list);
    unlock(thread_list_lock);
}

void del_thread (struct shim_thread * thread)
{
    if (IS_INTERNAL(thread) || list_empty(&thread->list))
        return;

    lock(thread_list_lock);
    list_del_init(&thread->list);
    unlock(thread_list_lock);
    put_thread(thread);
}

void add_simple_thread (struct shim_simple_thread * thread)
{
    if (!list_empty(&thread->list))
        return;

    struct shim_simple_thread * tmp, * prev = NULL;
    lock(thread_list_lock);

    /* keep it sorted */
    list_for_each_entry_reverse(tmp, &simple_thread_list, list) {
        if (tmp->tid == thread->tid) {
            unlock(thread_list_lock);
            return;
        }
        if (tmp->tid < thread->tid) {
            prev = tmp;
            break;
        }
    }

    get_simple_thread(thread);
    list_add(&thread->list, prev ? &prev->list : &simple_thread_list);
    unlock(thread_list_lock);
}

void del_simple_thread (struct shim_simple_thread * thread)
{
    if (list_empty(&thread->list))
        return;

    lock(thread_list_lock);
    list_del_init(&thread->list);
    unlock(thread_list_lock);
    put_simple_thread(thread);
}

int check_last_thread (struct shim_thread * self)
{
    struct shim_thread * tmp;

    lock(thread_list_lock);
    /* find out if there is any thread that is
       1) no current thread 2) in current vm
       3) still alive */
    list_for_each_entry(tmp, &thread_list, list)
        if (tmp->tid &&
            (!self || tmp->tid != self->tid) && tmp->in_vm && tmp->is_alive) {
            debug("check_last_thread: thread %d is alive\n", tmp->tid);
            unlock(thread_list_lock);
            return tmp->tid;
        }

    debug("this is the only thread\n", self->tid);
    unlock(thread_list_lock);
    return 0;
}

int walk_thread_list (int (*callback) (struct shim_thread *, void *, bool *),
                      void * arg, bool may_write)
{
    struct shim_thread * tmp, * n;
    bool srched = false;
    int ret;
    IDTYPE min_tid = 0;

relock:
    lock(thread_list_lock);

    list_for_each_entry_safe(tmp, n, &thread_list, list) {
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
    unlock(thread_list_lock);
out:
    return ret;
}

int walk_simple_thread_list (int (*callback) (struct shim_simple_thread *,
                                              void *, bool *),
                             void * arg, bool may_write)
{
    struct shim_simple_thread * tmp, * n;
    bool srched = false;
    int ret;
    IDTYPE min_tid = 0;

relock:
    lock(thread_list_lock);

    list_for_each_entry_safe(tmp, n, &simple_thread_list, list) {
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
    unlock(thread_list_lock);
out:
    return ret;
}

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

    DkThreadPrivate(real_thread->tcb);
    set_cur_thread(real_thread);

    debug("jump to the stack %p\n", real_thread->frameptr);
    debug("shim_vfork success (returning %d)\n", child);

    /* jump onto old stack
       we actually pop rbp as rsp, and later we will call 'ret' */
    asm volatile("movq %0, %%rbp\r\n"
                 "leaveq\r\n"
                 "retq\r\n" :
                 : "g"(real_thread->frameptr),
                   "a"(child)
                 : "memory");
}

DEFINE_MIGRATE_FUNC(thread)

MIGRATE_FUNC_BODY(thread)
{
    assert(size == sizeof(struct shim_thread));

    struct shim_thread * thread = (struct shim_thread *) obj;
    struct shim_thread * new_thread = NULL;

    if (recursive) {
        struct shim_vma * vma = NULL;
        lookup_supervma(thread->stack, thread->stack_top - thread->stack,
                        &vma);
        assert(vma);
        DO_MIGRATE(vma, vma, NULL, true);
    }

    unsigned long off = ADD_TO_MIGRATE_MAP(obj, *offset, size);

    if (ENTRY_JUST_CREATED(off)) {
        ADD_OFFSET(sizeof(struct shim_thread));
        ADD_FUNC_ENTRY(*offset);
        ADD_ENTRY(SIZE, sizeof(struct shim_thread));

        if (!dry) {
            new_thread = (struct shim_thread *) (base + *offset);
            memcpy(new_thread, thread, sizeof(struct shim_thread));

            INIT_LIST_HEAD(&new_thread->children);
            INIT_LIST_HEAD(&new_thread->siblings);
            INIT_LIST_HEAD(&new_thread->exited_children);
            INIT_LIST_HEAD(&new_thread->list);

            new_thread->in_vm  = false;
            new_thread->parent = NULL;
            new_thread->dummy  = NULL;
            new_thread->handle_map = NULL;
            new_thread->root   = NULL;
            new_thread->cwd    = NULL;
            new_thread->robust_list = NULL;

            if (!recursive)
                new_thread->tcb = NULL;

            REF_SET(new_thread->ref_count, 0);
        }

        for (int i = 0 ; i < NUM_SIGS ; i++) {
            if (thread->signal_handles[i].action) {
                ADD_OFFSET(sizeof(struct __kernel_sigaction));

                if (!dry) {
                    new_thread->signal_handles[i].action
                            = (struct __kernel_sigaction *) (base + *offset);

                    memcpy(new_thread->signal_handles[i].action,
                           thread->signal_handles[i].action,
                           sizeof(struct __kernel_sigaction));
                }
            }
        }

        int rlen, clen;
        const char * rpath = dentry_get_path(thread->root, true, &rlen);
        const char * cpath = dentry_get_path(thread->cwd, true, &clen);
        char * new_rpath, * new_cpath;

        ADD_OFFSET(rlen + 1);
        ADD_ENTRY(ADDR, (new_rpath = (void *) (base + *offset)));
        ADD_OFFSET(clen + 1);
        ADD_ENTRY(ADDR, (new_cpath = (void *) (base + *offset)));

        if (!dry) {
            memcpy(new_rpath, rpath, rlen + 1);
            memcpy(new_cpath, cpath, clen + 1);
        }
    } else if (!dry) {
        new_thread = (struct shim_thread *) (base + off);
    }

    if (new_thread && objp)
        *objp = (void *) new_thread;

    DO_MIGRATE_MEMBER(handle, thread, new_thread, exec, 0);

    DO_MIGRATE_MEMBER_IF_RECURSIVE(handle_map, thread, new_thread,
                                   handle_map, 1);
}
END_MIGRATE_FUNC

RESUME_FUNC_BODY(thread)
{
    unsigned long off = GET_FUNC_ENTRY();
    size_t size = GET_ENTRY(SIZE);
    assert(size == sizeof(struct shim_thread));
    struct shim_thread * thread = (struct shim_thread *) (base + off);

    RESUME_REBASE(thread->children);
    RESUME_REBASE(thread->siblings);
    RESUME_REBASE(thread->exited_children);
    RESUME_REBASE(thread->list);
    RESUME_REBASE(thread->exec);
    RESUME_REBASE(thread->handle_map);
    RESUME_REBASE(thread->signal_handles);

    const char * rpath = (const char *) GET_ENTRY(ADDR);
    const char * cpath = (const char *) GET_ENTRY(ADDR);
    RESUME_REBASE(rpath);
    RESUME_REBASE(cpath);
    path_lookupat(NULL, rpath, LOOKUP_OPEN, &thread->root);
    path_lookupat(NULL, cpath, LOOKUP_OPEN, &thread->cwd);

    create_lock(thread->lock);
    thread->scheduler_event = DkNotificationEventCreate(1);
    thread->exit_event = DkNotificationEventCreate(0);
    thread->child_exit_event = DkNotificationEventCreate(0);

    add_thread(thread);

    if (thread->exec)
        get_handle(thread->exec);

    if (thread->handle_map)
        get_handle_map(thread->handle_map);

#ifndef DEBUG_RESUME
    debug("thread: "
          "tid=%d,tgid=%d,parent=%d,stack=%p,frameptr=%p,tcb=%p\n",
          thread->tid, thread->tgid,
          thread->parent ? thread->parent->tid : thread->tid,
          thread->stack, thread->frameptr, thread->tcb);
#endif
}
END_RESUME_FUNC

DEFINE_MIGRATE_FUNC(running_thread)

MIGRATE_FUNC_BODY(running_thread)
{
    assert(size == sizeof(struct shim_thread));

    struct shim_thread * thread = (struct shim_thread *) obj;
    struct shim_thread * new_thread = NULL;
    struct shim_thread ** thread_obj = &new_thread;

    DO_MIGRATE(thread, thread, thread_obj, recursive);
    ADD_FUNC_ENTRY(new_thread);

    __libc_tcb_t * tcb = thread->tcb;
    if (tcb && lookup_supervma(tcb, sizeof(__libc_tcb_t), NULL) < 0) {
        ADD_OFFSET(sizeof(__libc_tcb_t));
        ADD_ENTRY(ADDR, base + *offset);
        if (!dry) {
            __libc_tcb_t * new_tcb = (void *) (base + *offset);
            memcpy(new_tcb, tcb, sizeof(__libc_tcb_t));
        }
    } else {
        ADD_ENTRY(ADDR, NULL);
    }
}
END_MIGRATE_FUNC

int resume_wrapper (void * param)
{
    struct shim_thread * thread = (struct shim_thread *) param;
    assert(thread);

    __libc_tcb_t * libc_tcb = (__libc_tcb_t *) thread->tcb;
    assert(libc_tcb);
    shim_tcb_t * tcb = &libc_tcb->shim_tcb;
    assert(tcb->context.sp);

    thread->in_vm = thread->is_alive = true;
    allocate_tls(libc_tcb, thread);
    debug_setbuf(tcb, true);

    DkObjectsWaitAny(1, &thread_start_event, NO_TIMEOUT);

    restore_context(&tcb->context);
    return 0;
}

RESUME_FUNC_BODY(running_thread)
{
    struct shim_thread * thread = (void *) GET_FUNC_ENTRY();
    RESUME_REBASE(thread);
    struct shim_thread * cur_thread = get_cur_thread();
    thread->in_vm = true;

    get_thread(thread);

    void * new_tcb = (void *) GET_ENTRY(ADDR);
    if (new_tcb) {
        RESUME_REBASE(new_tcb);
        thread->tcb = new_tcb;
    }

    if (cur_thread) {
        PAL_HANDLE handle = DkThreadCreate(resume_wrapper, thread, 0);
        if (!thread)
            return -PAL_ERRNO;

        thread->pal_handle = handle;
    } else {
        __libc_tcb_t * libc_tcb = (__libc_tcb_t *) thread->tcb;

        if (libc_tcb) {
            shim_tcb_t * tcb = &libc_tcb->shim_tcb;
            assert(tcb->context.sp);
            tcb->debug_buf = SHIM_GET_TLS()->debug_buf;
            allocate_tls(libc_tcb, thread);
            debug_setprefix(tcb);
        } else {
            set_cur_thread(thread);
        }

        thread->in_vm = thread->is_alive = true;
        thread->pal_handle = PAL_CB(first_thread);
    }

#ifdef DEBUG_RESUME
    debug("thread %d is attached to the current process\n", thread->tid);
#endif
}
END_RESUME_FUNC

DEFINE_MIGRATE_FUNC(all_running_threads)

MIGRATE_FUNC_BODY(all_running_threads)
{
    struct shim_thread * thread;

    lock(thread_list_lock);

    list_for_each_entry(thread, &thread_list, list) {
        if (!thread->in_vm || !thread->is_alive)
            continue;

        DO_MIGRATE(running_thread, thread, NULL, recursive);
        DO_MIGRATE(handle_map, thread->handle_map, NULL, recursive);
    }

    unlock(thread_list_lock);
}
END_MIGRATE_FUNC

RESUME_FUNC_BODY(all_running_threads)
{
    /* useless */
}
END_RESUME_FUNC
