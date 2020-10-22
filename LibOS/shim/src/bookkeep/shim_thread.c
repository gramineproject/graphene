/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains code for maintaining bookkeeping of threads in library OS.
 */

#include <stddef.h> /* linux/signal.h misses this dependency (for size_t), at least on Ubuntu 16.04.
                     * We must include it ourselves before including linux/signal.h.
                     */

#include <linux/signal.h>

#include "cpu.h"
#include "list.h"
#include "pal.h"
#include "shim_checkpoint.h"
#include "shim_context.h"
#include "shim_defs.h"
#include "shim_fs.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_lock.h"
#include "shim_thread.h"
#include "shim_utils.h"
#include "shim_vma.h"
#include "toml.h"

static IDTYPE tid_alloc_idx __attribute_migratable = 0;

static LISTP_TYPE(shim_thread) thread_list = LISTP_INIT;
struct shim_lock thread_list_lock;

static IDTYPE internal_tid_alloc_idx = INTERNAL_TID_BASE;

PAL_HANDLE thread_start_event = NULL;

//#define DEBUG_REF

#ifdef DEBUG_REF
#define DEBUG_PRINT_REF_COUNT(rc) debug("%s %p ref_count = %d\n", __func__, handles, rc)
#else
#define DEBUG_PRINT_REF_COUNT(rc) __UNUSED(rc)
#endif

int init_thread(void) {
    if (!create_lock(&thread_list_lock)) {
        return -ENOMEM;
    }

    struct shim_thread* cur_thread = get_cur_thread();
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

void dump_threads(void) {
    struct shim_thread* tmp;

    lock(&thread_list_lock);
    LISTP_FOR_EACH_ENTRY(tmp, &thread_list, list) {
        debug("thread %d, vmid = %d, pgid = %d, ppid = %d, tgid = %d, in_vm = %d\n", tmp->tid,
              tmp->vmid, tmp->pgid, tmp->ppid, tmp->tgid, tmp->in_vm);
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

    lock(&thread_list_lock);
    while (1) {
        IDTYPE new_idx_hint = READ_ONCE(tid_alloc_idx) + 1;
        idx = allocate_ipc_id(new_idx_hint, 0);
        if (idx) {
            break;
        }
        idx = allocate_ipc_id(1, new_idx_hint);
        if (idx) {
            break;
        }

        unlock(&thread_list_lock);
        /* We've probably run out of pids - let's get a new range. */
        if (ipc_lease_send() < 0) {
            return 0;
        }
        lock(&thread_list_lock);
    }

    tid_alloc_idx = idx;

    unlock(&thread_list_lock);
    return idx;
}

static IDTYPE get_internal_pid(void) {
    lock(&thread_list_lock);
    internal_tid_alloc_idx++;
    IDTYPE idx = internal_tid_alloc_idx;
    unlock(&thread_list_lock);
    assert(is_internal_tid(idx));
    return idx;
}

static struct shim_thread* alloc_new_thread(void) {
    struct shim_thread* thread = calloc(1, sizeof(struct shim_thread));
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

static struct shim_signal_handles* alloc_default_signal_handles(void) {
    struct shim_signal_handles* handles = malloc(sizeof(*handles));
    if (!handles) {
        return NULL;
    }

    if (!create_lock(&handles->lock)) {
        free(handles);
        return NULL;
    }
    REF_SET(handles->ref_count, 1);
    for (size_t i = 0; i < ARRAY_SIZE(handles->actions); i++) {
        sigaction_make_defaults(&handles->actions[i]);
    }

    return handles;
}

struct shim_thread* get_new_thread(IDTYPE new_tid) {
    int ret;

    if (!new_tid) {
        new_tid = get_pid();
        if (!new_tid) {
            debug("get_new_thread: could not allocate a pid!\n");
            return NULL;
        }
    }

    struct shim_thread* thread = alloc_new_thread();
    if (!thread) {
        release_ipc_id(new_tid);
        return NULL;
    }

    struct shim_thread* cur_thread = get_cur_thread();
    thread->tid = new_tid;

    if (cur_thread) {
        /* The newly created thread will be in the same thread group
           (process group as well) with its parent */
        thread->pgid      = cur_thread->pgid;
        thread->ppid      = cur_thread->tgid;
        thread->tgid      = cur_thread->tgid;
        thread->uid       = cur_thread->uid;
        thread->gid       = cur_thread->gid;
        thread->euid      = cur_thread->euid;
        thread->egid      = cur_thread->egid;
        thread->parent    = cur_thread;
        thread->stack     = cur_thread->stack;
        thread->stack_top = cur_thread->stack_top;
        thread->stack_red = cur_thread->stack_red;
        thread->cwd       = cur_thread->cwd;
        thread->root      = cur_thread->root;
        thread->umask     = cur_thread->umask;
        thread->exec      = cur_thread->exec;
        get_handle(cur_thread->exec);

        thread->signal_handles = cur_thread->signal_handles;
        get_signal_handles(thread->signal_handles);

        memcpy(&thread->signal_mask, &cur_thread->signal_mask, sizeof(sigset_t));

        get_dentry(cur_thread->cwd);
        get_dentry(cur_thread->root);

        struct shim_handle_map* map = get_cur_handle_map(cur_thread);
        assert(map);
        set_handle_map(thread, map);
    } else {
        /* default pid and pgid equals to tid */
        thread->pgid = thread->tgid = new_tid;
        thread->ppid = 0;
        /* This case should fall back to the global root of the file system */
        path_lookupat(NULL, "/", 0, &thread->root, NULL);

        assert(g_manifest_root);
        char* fs_start_dir = NULL;
        ret = toml_string_in(g_manifest_root, "fs.start_dir", &fs_start_dir);
        if (ret < 0) {
            debug("Cannot parse \'fs.start_dir\' (the value must be put in double quotes!)\n");
            goto out_error;
        }

        if (fs_start_dir) {
            path_lookupat(NULL, fs_start_dir, 0, &thread->cwd, NULL);
            free(fs_start_dir);
        } else if (thread->root) {
            get_dentry(thread->root);
            thread->cwd = thread->root;
        }

        thread->signal_handles = alloc_default_signal_handles();
        if (!thread->signal_handles) {
            goto out_error;
        }
    }

    if (!create_lock(&thread->lock)) {
        goto out_error;
    }

    thread->vmid             = g_process_ipc_info.vmid;
    thread->scheduler_event  = DkNotificationEventCreate(PAL_TRUE);
    thread->exit_event       = DkNotificationEventCreate(PAL_FALSE);
    thread->child_exit_event = DkNotificationEventCreate(PAL_FALSE);
    return thread;

out_error:
    if (thread->handle_map) {
        put_handle_map(thread->handle_map);
    }
    if (thread->root) {
        put_dentry(thread->root);
    }
    if (thread->cwd) {
        put_dentry(thread->cwd);
    }
    if (thread->signal_handles) {
        put_signal_handles(thread->signal_handles);
    }
    if (thread->exec) {
        put_handle(thread->exec);
    }
    release_ipc_id(new_tid);
    free(thread);
    return NULL;
}

struct shim_thread* get_new_internal_thread(void) {
    IDTYPE new_tid = get_internal_pid();
    if (!new_tid) {
        return NULL;
    }

    struct shim_thread* thread = alloc_new_thread();
    if (!thread)
        return NULL;

    thread->vmid  = g_process_ipc_info.vmid;
    thread->tid   = new_tid;
    thread->in_vm = thread->is_alive = true;
    if (!create_lock(&thread->lock)) {
        free(thread);
        return NULL;
    }
    thread->exit_event = DkNotificationEventCreate(PAL_FALSE);
    return thread;
}

void get_signal_handles(struct shim_signal_handles* handles) {
    int ref_count = REF_INC(handles->ref_count);
    DEBUG_PRINT_REF_COUNT(ref_count);
}

void put_signal_handles(struct shim_signal_handles* handles) {
    int ref_count = REF_DEC(handles->ref_count);

    DEBUG_PRINT_REF_COUNT(ref_count);

    if (!ref_count) {
        destroy_lock(&handles->lock);
        free(handles);
    }
}

void get_thread(struct shim_thread* thread) {
    int ref_count = REF_INC(thread->ref_count);
    DEBUG_PRINT_REF_COUNT(ref_count);
}

void put_thread(struct shim_thread* thread) {
    int ref_count = REF_DEC(thread->ref_count);

    DEBUG_PRINT_REF_COUNT(ref_count);

    if (!ref_count) {
        if (thread->pal_handle && thread->pal_handle != PAL_CB(first_thread))
            DkObjectClose(thread->pal_handle);

        if (thread->scheduler_event)
            DkObjectClose(thread->scheduler_event);
        if (thread->exit_event)
            DkObjectClose(thread->exit_event);
        if (thread->child_exit_event)
            DkObjectClose(thread->child_exit_event);

        if (thread->handle_map) {
            put_handle_map(thread->handle_map);
        }
        if (thread->root) {
            put_dentry(thread->root);
        }
        if (thread->cwd) {
            put_dentry(thread->cwd);
        }

        if (thread->signal_handles) {
            put_signal_handles(thread->signal_handles);
        }

        if (thread->exec)
            put_handle(thread->exec);

        if (!is_internal(thread))
            release_ipc_id(thread->tid);

        if (lock_created(&thread->lock)) {
            destroy_lock(&thread->lock);
        }

        free(thread);
    }
}

void set_as_child(struct shim_thread* parent, struct shim_thread* child) {
    if (!parent)
        parent = get_cur_thread();

    get_thread(parent);
    get_thread(child);

    lock(&child->lock);
    child->ppid   = parent->tid;
    child->parent = parent;

    lock(&parent->lock);
    LISTP_ADD_TAIL(child, &parent->children, siblings);
    unlock(&parent->lock);

    unlock(&child->lock);
}

void add_thread(struct shim_thread* thread) {
    if (is_internal(thread) || !LIST_EMPTY(thread, list))
        return;

    struct shim_thread* tmp;
    struct shim_thread* prev = NULL;
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

void del_thread(struct shim_thread* thread) {
    debug("del_thread(%p, %d, %ld)\n", thread, thread ? (int)thread->tid : -1,
          __atomic_load_n(&thread->ref_count.counter, __ATOMIC_SEQ_CST));

    if (is_internal(thread)) {
        debug("del_thread: internal\n");
        return;
    }

    lock(&thread_list_lock);
    if (!LIST_EMPTY(thread, list)) {
        LISTP_DEL_INIT(thread, &thread_list, list);
    }
    unlock(&thread_list_lock);
    put_thread(thread);
}

/*
 * Atomically marks current thread as dead and returns whether it was the last thread alive.
 */
bool mark_self_dead(void) {
    struct shim_thread* self = get_cur_thread();
    bool ret = true;

    lock(&thread_list_lock);

    lock(&self->lock);
    self->is_alive = false;
    unlock(&self->lock);

    struct shim_thread* thread;
    LISTP_FOR_EACH_ENTRY(thread, &thread_list, list) {
        lock(&thread->lock);
        if (thread->in_vm && thread != self && thread->is_alive) {
            unlock(&thread->lock);
            ret = false;
            break;
        }
        unlock(&thread->lock);
    }

    unlock(&thread_list_lock);
    return ret;
}

/*
 * Checks whether there are any other threads on `thread_list`.
 */
bool check_last_thread(void) {
    struct shim_thread* self = get_cur_thread();
    bool ret = true;

    lock(&thread_list_lock);

    struct shim_thread* thread;
    LISTP_FOR_EACH_ENTRY(thread, &thread_list, list) {
        lock(&thread->lock);
        if (thread->in_vm && thread != self) {
            unlock(&thread->lock);
            ret = false;
            break;
        }
        unlock(&thread->lock);
    }
    unlock(&thread_list_lock);
    return ret;
}

/* This function is called by Async Helper thread to wait on thread->clear_child_tid_pal to be
 * zeroed (PAL does it when thread finally exits). Since it is a callback to Async Helper thread,
 * this function must follow the `void (*callback) (IDTYPE caller, void* arg)` signature. */
void cleanup_thread(IDTYPE caller, void* arg) {
    __UNUSED(caller);

    struct shim_thread* thread = (struct shim_thread*)arg;
    assert(thread);

    /* wait on clear_child_tid_pal; this signals that PAL layer exited child thread */
    while (__atomic_load_n(&thread->clear_child_tid_pal, __ATOMIC_RELAXED) != 0)
        CPU_RELAX();

    /* notify parent if any */
    release_clear_child_tid(thread->clear_child_tid);

    /* Clean up the thread itself - this call will remove it from `thread_list`. */
    del_thread(thread);
}

int walk_thread_list(int (*callback)(struct shim_thread*, void*), void* arg, bool one_shot) {
    struct shim_thread* tmp;
    struct shim_thread* n;
    bool success = false;
    int ret = -ESRCH;

    lock(&thread_list_lock);

    LISTP_FOR_EACH_ENTRY_SAFE(tmp, n, &thread_list, list) {
        ret = callback(tmp, arg);
        if (ret < 0 && ret != -ESRCH) {
            goto out;
        }
        if (ret > 0) {
            if (one_shot) {
                ret = 0;
                goto out;
            }
            success = true;
        }
    }

    ret = success ? 0 : -ESRCH;
out:
    unlock(&thread_list_lock);
    return ret;
}

BEGIN_CP_FUNC(signal_handles) {
    __UNUSED(size);
    assert(size == sizeof(struct shim_signal_handles));

    struct shim_signal_handles* handles = (struct shim_signal_handles*)obj;
    struct shim_signal_handles* new_handles = NULL;

    size_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off = ADD_CP_OFFSET(sizeof(struct shim_signal_handles));
        ADD_TO_CP_MAP(obj, off);
        new_handles = (struct shim_signal_handles*)(base + off);

        lock(&handles->lock);

        memcpy(new_handles, handles, sizeof(*handles));
        clear_lock(&new_handles->lock);
        REF_SET(new_handles->ref_count, 0);

        unlock(&handles->lock);

        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_handles = (struct shim_signal_handles*)(base + off);
    }

    if (objp) {
        *objp = (void*)new_handles;
    }
}
END_CP_FUNC(signal_handles)

BEGIN_RS_FUNC(signal_handles) {
    __UNUSED(offset);
    __UNUSED(rebase);
    struct shim_signal_handles* handles = (void*)(base + GET_CP_FUNC_ENTRY());

    if (!create_lock(&handles->lock)) {
        return -ENOMEM;
    }
}
END_RS_FUNC(signal_handles)

BEGIN_CP_FUNC(thread) {
    __UNUSED(size);
    assert(size == sizeof(struct shim_thread));

    struct shim_thread* thread = (struct shim_thread*)obj;
    struct shim_thread* new_thread = NULL;

    size_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off = ADD_CP_OFFSET(sizeof(struct shim_thread));
        ADD_TO_CP_MAP(obj, off);
        new_thread = (struct shim_thread*)(base + off);
        memcpy(new_thread, thread, sizeof(struct shim_thread));

        INIT_LISTP(&new_thread->children);
        INIT_LIST_HEAD(new_thread, siblings);
        INIT_LISTP(&new_thread->exited_children);
        INIT_LIST_HEAD(new_thread, list);

        new_thread->in_vm      = false;
        new_thread->parent     = NULL;
        new_thread->handle_map = NULL;
        new_thread->root       = NULL;
        new_thread->cwd        = NULL;
        memset(&new_thread->signal_queue, 0, sizeof(new_thread->signal_queue));
        new_thread->robust_list = NULL;
        REF_SET(new_thread->ref_count, 0);

        DO_CP_MEMBER(signal_handles, thread, new_thread, signal_handles);

        DO_CP_MEMBER(handle, thread, new_thread, exec);
        DO_CP_MEMBER(handle_map, thread, new_thread, handle_map);
        DO_CP_MEMBER(dentry, thread, new_thread, root);
        DO_CP_MEMBER(dentry, thread, new_thread, cwd);
        ADD_CP_FUNC_ENTRY(off);

        if (thread->shim_tcb) {
            size_t toff = ADD_CP_OFFSET(sizeof(shim_tcb_t));
            new_thread->shim_tcb = (void*)(base + toff);
            struct shim_tcb* new_tcb = new_thread->shim_tcb;
            memcpy(new_tcb, thread->shim_tcb, sizeof(*new_tcb));
            /* don't export stale pointers */
            new_tcb->self      = NULL;
            new_tcb->tp        = NULL;
            new_tcb->debug_buf = NULL;
            new_tcb->vma_cache = NULL;
        }
    } else {
        new_thread = (struct shim_thread*)(base + off);
    }

    if (objp)
        *objp = (void*)new_thread;
}
END_CP_FUNC(thread)

BEGIN_RS_FUNC(thread) {
    struct shim_thread* thread = (void*)(base + GET_CP_FUNC_ENTRY());
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
    thread->scheduler_event  = DkNotificationEventCreate(PAL_TRUE);
    thread->exit_event       = DkNotificationEventCreate(PAL_FALSE);
    thread->child_exit_event = DkNotificationEventCreate(PAL_FALSE);

    if (thread->exec)
        get_handle(thread->exec);

    if (thread->handle_map)
        get_handle_map(thread->handle_map);

    if (thread->root)
        get_dentry(thread->root);

    if (thread->cwd)
        get_dentry(thread->cwd);

    if (thread->signal_handles) {
        get_signal_handles(thread->signal_handles);
    }

    thread->in_vm = true;
    thread->vmid = g_process_ipc_info.vmid;

    add_thread(thread);

    if (thread->set_child_tid) {
        /* CLONE_CHILD_SETTID */
        *thread->set_child_tid = thread->tid;
        thread->set_child_tid = NULL;
    }

    assert(!get_cur_thread());

    if (thread->shim_tcb) {
        CP_REBASE(thread->shim_tcb);

        /* fork case */
        shim_tcb_t* tcb = shim_get_tcb();
        memcpy(tcb, thread->shim_tcb, sizeof(*tcb));
        __shim_tcb_init(tcb);
        set_cur_thread(thread);

        assert(tcb->context.regs && shim_context_get_sp(&tcb->context));
        update_fs_base(tcb->context.fs_base);
        /* Temporarily disable preemption until the thread resumes. */
        __disable_preempt(tcb);
        debug_setbuf(tcb, NULL);
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
        if (thread->signal_handles)
            thread_sigaction_reset_on_execve(thread);

        set_cur_thread(thread);
        debug_setbuf(thread->shim_tcb, NULL);
    }

    thread->in_vm = thread->is_alive = true;
    thread->pal_handle = PAL_CB(first_thread);

    DEBUG_RS("tid=%d,tgid=%d,parent=%d,stack=%p,frameptr=%p,tcb=%p,shim_tcb=%p", thread->tid,
             thread->tgid, thread->parent ? thread->parent->tid : thread->tid, thread->stack,
             thread->frameptr, thread->tcb, thread->shim_tcb);

}
END_RS_FUNC(thread)
