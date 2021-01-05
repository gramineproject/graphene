/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

/*
 * This file contains code for maintaining bookkeeping of threads in library OS.
 */

#include "api.h"
#include "assert.h"
#include "cpu.h"
#include "list.h"
#include "pal.h"
#include "shim_checkpoint.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_ipc.h"
#include "shim_lock.h"
#include "shim_process.h"
#include "shim_signal.h"
#include "shim_thread.h"

static IDTYPE g_tid_alloc_idx = 0;

/* TODO: consider changing this list to a tree. */
static LISTP_TYPE(shim_thread) g_thread_list = LISTP_INIT;
struct shim_lock g_thread_list_lock;

static IDTYPE g_internal_tid_alloc_idx = INTERNAL_TID_BASE;

//#define DEBUG_REF

#ifdef DEBUG_REF
#define DEBUG_PRINT_REF_COUNT(rc) debug("%s %p ref_count = %d\n", __func__, dispositions, rc)
#else
#define DEBUG_PRINT_REF_COUNT(rc) __UNUSED(rc)
#endif

static struct shim_signal_dispositions* alloc_default_signal_dispositions(void) {
    struct shim_signal_dispositions* dispositions = malloc(sizeof(*dispositions));
    if (!dispositions) {
        return NULL;
    }

    if (!create_lock(&dispositions->lock)) {
        free(dispositions);
        return NULL;
    }
    REF_SET(dispositions->ref_count, 1);
    for (size_t i = 0; i < ARRAY_SIZE(dispositions->actions); i++) {
        sigaction_make_defaults(&dispositions->actions[i]);
    }

    return dispositions;
}

static IDTYPE get_new_tid(void) {
    IDTYPE idx;

    lock(&g_thread_list_lock);
    while (1) {
        IDTYPE new_idx_hint = g_tid_alloc_idx + 1;
        idx = allocate_ipc_id(new_idx_hint, 0);
        if (idx) {
            break;
        }
        idx = allocate_ipc_id(1, new_idx_hint);
        if (idx) {
            break;
        }

        unlock(&g_thread_list_lock);
        /* We've probably run out of pids - let's get a new range. */
        if (ipc_lease_send() < 0) {
            return 0;
        }
        lock(&g_thread_list_lock);
    }

    g_tid_alloc_idx = idx;

    unlock(&g_thread_list_lock);
    return idx;
}

static struct shim_thread* alloc_new_thread(void) {
    struct shim_thread* thread = calloc(1, sizeof(struct shim_thread));
    if (!thread) {
        return NULL;
    }

    if (!create_lock(&thread->lock)) {
        free(thread);
        return NULL;
    }

    REF_SET(thread->ref_count, 1);
    INIT_LIST_HEAD(thread, list);
    /* default value as sigalt stack isn't specified yet */
    thread->signal_altstack.ss_flags = SS_DISABLE;
    return thread;
}

static int init_main_thread(void) {
    struct shim_thread* cur_thread = get_cur_thread();
    if (cur_thread) {
        /* Thread already initialized (e.g. received via checkpoint). */
        add_thread(cur_thread);
        return init_ns_pid();
    }

    cur_thread = alloc_new_thread();
    if (!cur_thread) {
        return -ENOMEM;
    }

    cur_thread->tid = get_new_tid();
    if (!cur_thread->tid) {
        debug("Cannot allocate pid for the initial thread!\n");
        put_thread(cur_thread);
        return -ESRCH;
    }
    g_process.pid = cur_thread->tid;
    __atomic_store_n(&g_process.pgid, g_process.pid, __ATOMIC_RELEASE);

    /* Default user and group ids are `0` and already set. */

    cur_thread->signal_dispositions = alloc_default_signal_dispositions();
    if (!cur_thread->signal_dispositions) {
        put_thread(cur_thread);
        return -ENOMEM;
    }

    __sigset_t set;
    __sigemptyset(&set);
    lock(&cur_thread->lock);
    set_sig_mask(cur_thread, &set);
    unlock(&cur_thread->lock);

    cur_thread->scheduler_event = DkNotificationEventCreate(PAL_TRUE);
    if (!cur_thread->scheduler_event) {
        put_thread(cur_thread);
        return -ENOMEM;
    }

    cur_thread->pal_handle = PAL_CB(first_thread);

    set_cur_thread(cur_thread);
    add_thread(cur_thread);

    return 0;
}

int init_threading(void) {
    if (!create_lock(&g_thread_list_lock)) {
        return -ENOMEM;
    }

    return init_main_thread();
}

static struct shim_thread* __lookup_thread(IDTYPE tid) {
    assert(locked(&g_thread_list_lock));

    struct shim_thread* tmp;

    LISTP_FOR_EACH_ENTRY(tmp, &g_thread_list, list) {
        if (tmp->tid == tid) {
            get_thread(tmp);
            return tmp;
        }
    }

    return NULL;
}

struct shim_thread* lookup_thread(IDTYPE tid) {
    lock(&g_thread_list_lock);
    struct shim_thread* thread = __lookup_thread(tid);
    unlock(&g_thread_list_lock);
    return thread;
}

static IDTYPE get_new_internal_tid(void) {
    IDTYPE idx = __atomic_add_fetch(&g_internal_tid_alloc_idx, 1, __ATOMIC_RELAXED);
    if (!is_internal_tid(idx)) {
        return 0;
    }
    return idx;
}

struct shim_thread* get_new_thread(void) {
    struct shim_thread* thread = alloc_new_thread();
    if (!thread) {
        return NULL;
    }

    thread->tid = get_new_tid();
    if (!thread->tid) {
        debug("get_new_thread: could not allocate a tid!\n");
        put_thread(thread);
        return NULL;
    }

    struct shim_thread* cur_thread = get_cur_thread();
    lock(&cur_thread->lock);

    thread->uid       = cur_thread->uid;
    thread->gid       = cur_thread->gid;
    thread->euid      = cur_thread->euid;
    thread->egid      = cur_thread->egid;

    thread->stack     = cur_thread->stack;
    thread->stack_top = cur_thread->stack_top;
    thread->stack_red = cur_thread->stack_red;

    thread->signal_dispositions = cur_thread->signal_dispositions;
    get_signal_dispositions(thread->signal_dispositions);

    /* No need for this lock as we have just created `thread`, but `set_sig_mask` has an assert for
     * it. Also there is no problem with locking order as `thread` is not yet shared. */
    lock(&thread->lock);
    set_sig_mask(thread, &cur_thread->signal_mask);
    unlock(&thread->lock);

    struct shim_handle_map* map = get_thread_handle_map(cur_thread);
    assert(map);
    set_handle_map(thread, map);

    unlock(&cur_thread->lock);

    thread->scheduler_event = DkNotificationEventCreate(PAL_TRUE);
    if (!thread->scheduler_event) {
        put_thread(thread);
        return NULL;
    }

    return thread;
}

struct shim_thread* get_new_internal_thread(void) {
    struct shim_thread* thread = alloc_new_thread();
    if (!thread) {
        return NULL;
    }

    thread->tid = get_new_internal_tid();
    if (!thread->tid) {
        put_thread(thread);
        return NULL;
    }

    return thread;
}

void get_signal_dispositions(struct shim_signal_dispositions* dispositions) {
    int ref_count = REF_INC(dispositions->ref_count);
    DEBUG_PRINT_REF_COUNT(ref_count);
}

void put_signal_dispositions(struct shim_signal_dispositions* dispositions) {
    int ref_count = REF_DEC(dispositions->ref_count);

    DEBUG_PRINT_REF_COUNT(ref_count);

    if (!ref_count) {
        destroy_lock(&dispositions->lock);
        free(dispositions);
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
        assert(LIST_EMPTY(thread, list));

        if (thread->pal_handle && thread->pal_handle != PAL_CB(first_thread))
            DkObjectClose(thread->pal_handle);

        if (thread->handle_map) {
            put_handle_map(thread->handle_map);
        }

        if (thread->signal_dispositions) {
            put_signal_dispositions(thread->signal_dispositions);
        }

        clear_signal_queue(&thread->signal_queue);

        /* `signal_altstack` is provided by the user, no need for a clean up. */

        if (thread->robust_list) {
            release_robust_list(thread->robust_list);
        }

        if (thread->scheduler_event) {
            DkObjectClose(thread->scheduler_event);
        }

        /* `wake_queue` is only meaningful when `thread` is part of some wake up queue (is just
         * being woken up), which would imply `ref_count > 0`. */

        if (thread->tid && !is_internal(thread)) {
            release_ipc_id(thread->tid);
        }

        destroy_lock(&thread->lock);

        free(thread);
    }
}

void add_thread(struct shim_thread* thread) {
    assert(!is_internal(thread) && LIST_EMPTY(thread, list));

    struct shim_thread* tmp;
    struct shim_thread* prev = NULL;
    lock(&g_thread_list_lock);

    /* keep it sorted */
    LISTP_FOR_EACH_ENTRY_REVERSE(tmp, &g_thread_list, list) {
        if (tmp->tid < thread->tid) {
            prev = tmp;
            break;
        }
        assert(tmp->tid != thread->tid);
    }

    get_thread(thread);
    LISTP_ADD_AFTER(thread, prev, &g_thread_list, list);
    unlock(&g_thread_list_lock);
}

/*
 * Checks whether there are any other threads on `g_thread_list` (i.e. if we are the last thread).
 * If `mark_self_dead` is true additionally takes us off the `g_thread_list`.
 */
bool check_last_thread(bool mark_self_dead) {
    struct shim_thread* self = get_cur_thread();
    bool ret = true;

    lock(&g_thread_list_lock);

    struct shim_thread* thread;
    LISTP_FOR_EACH_ENTRY(thread, &g_thread_list, list) {
        if (thread != self) {
            ret = false;
            break;
        }
    }

    if (mark_self_dead) {
        LISTP_DEL_INIT(self, &g_thread_list, list);
    }

    unlock(&g_thread_list_lock);

    if (mark_self_dead) {
        put_thread(self);
    }

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

    if (thread->robust_list) {
        release_robust_list(thread->robust_list);
        thread->robust_list = NULL;
    }

    /* notify parent if any */
    release_clear_child_tid(thread->clear_child_tid);

    /* Put down our (possibly last) reference to this thread - we got the ownership from the caller.
     */
    put_thread(thread);
}

int walk_thread_list(int (*callback)(struct shim_thread*, void*), void* arg, bool one_shot) {
    struct shim_thread* tmp;
    struct shim_thread* n;
    bool success = false;
    int ret = -ESRCH;

    lock(&g_thread_list_lock);

    LISTP_FOR_EACH_ENTRY_SAFE(tmp, n, &g_thread_list, list) {
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
    unlock(&g_thread_list_lock);
    return ret;
}

BEGIN_CP_FUNC(signal_dispositions) {
    __UNUSED(size);
    assert(size == sizeof(struct shim_signal_dispositions));

    struct shim_signal_dispositions* dispositions = (struct shim_signal_dispositions*)obj;
    struct shim_signal_dispositions* new_dispositions = NULL;

    size_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off = ADD_CP_OFFSET(sizeof(struct shim_signal_dispositions));
        ADD_TO_CP_MAP(obj, off);
        new_dispositions = (struct shim_signal_dispositions*)(base + off);

        lock(&dispositions->lock);

        *new_dispositions = *dispositions;
        clear_lock(&new_dispositions->lock);
        REF_SET(new_dispositions->ref_count, 0);

        unlock(&dispositions->lock);

        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_dispositions = (struct shim_signal_dispositions*)(base + off);
    }

    if (objp) {
        *objp = (void*)new_dispositions;
    }
}
END_CP_FUNC(signal_dispositions)

BEGIN_RS_FUNC(signal_dispositions) {
    __UNUSED(offset);
    __UNUSED(rebase);
    struct shim_signal_dispositions* dispositions = (void*)(base + GET_CP_FUNC_ENTRY());

    if (!create_lock(&dispositions->lock)) {
        return -ENOMEM;
    }
}
END_RS_FUNC(signal_dispositions)

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
        *new_thread = *thread;

        INIT_LIST_HEAD(new_thread, list);

        new_thread->pal_handle = NULL;

        new_thread->handle_map = NULL;
        memset(&new_thread->signal_queue, 0, sizeof(new_thread->signal_queue));
        new_thread->robust_list = NULL;
        REF_SET(new_thread->ref_count, 0);

        DO_CP_MEMBER(signal_dispositions, thread, new_thread, signal_dispositions);

        DO_CP_MEMBER(handle_map, thread, new_thread, handle_map);

        ADD_CP_FUNC_ENTRY(off);

        if (thread->shim_tcb) {
            size_t toff = ADD_CP_OFFSET(sizeof(shim_tcb_t));
            new_thread->shim_tcb = (void*)(base + toff);
            struct shim_tcb* new_tcb = new_thread->shim_tcb;
            *new_tcb = *thread->shim_tcb;
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

    CP_REBASE(thread->list);
    CP_REBASE(thread->handle_map);
    CP_REBASE(thread->signal_dispositions);

    if (!create_lock(&thread->lock)) {
        return -ENOMEM;
    }

    thread->scheduler_event = DkNotificationEventCreate(PAL_TRUE);
    if (!thread->scheduler_event) {
        return -ENOMEM;
    }

    if (thread->handle_map) {
        get_handle_map(thread->handle_map);
    }

    if (thread->signal_dispositions) {
        get_signal_dispositions(thread->signal_dispositions);
    }

    if (thread->set_child_tid) {
        *thread->set_child_tid = thread->tid;
        thread->set_child_tid = NULL;
    }

    assert(!get_cur_thread());

    if (thread->shim_tcb) {
        /* fork case */
        CP_REBASE(thread->shim_tcb);

        shim_tcb_t* tcb = shim_get_tcb();
        *tcb = *thread->shim_tcb;
        __shim_tcb_init(tcb);

        assert(tcb->context.regs && shim_context_get_sp(&tcb->context));
        update_tls_base(tcb->context.tls_base);
        /* Temporarily disable preemption until the thread resumes. */
        __disable_preempt(tcb);
    } else {
        /* execve case */
        /* In execve case, the following holds:
         * stack = NULL
         * stack_top = NULL
         * frameptr = NULL
         * tcb = NULL
         * shim_tcb = NULL
         * in_vm = false
         */
        if (thread->signal_dispositions)
            thread_sigaction_reset_on_execve(thread);
    }

    thread->pal_handle = PAL_CB(first_thread);

    set_cur_thread(thread);

    int ret = debug_setbuf(thread->shim_tcb, NULL);
    if (ret < 0) {
        return ret;
    }
}
END_RS_FUNC(thread)
