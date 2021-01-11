/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#ifndef _SHIM_THREAD_H_
#define _SHIM_THREAD_H_

#include <linux/futex.h>
#include <linux/signal.h>
#include <stdbool.h>
#include <stdint.h>

#include "api.h"
#include "pal.h"
#include "list.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_signal.h"
#include "shim_tcb.h"
#include "shim_types.h"

#define WAKE_QUEUE_TAIL ((void*)1)
/* If next is NULL, then this node is not on any queue.
 * Otherwise it is a valid pointer to the next node or WAKE_QUEUE_TAIL. */
struct wake_queue_node {
    struct wake_queue_node* next;
};
struct wake_queue_head {
    struct wake_queue_node* first;
};

struct shim_signal_dispositions {
    struct __kernel_sigaction actions[NUM_SIGS];
    struct shim_lock lock;
    REFTYPE ref_count;
};

/* For more info see: man signal(7) */
#define MAX_SIGNAL_LOG 32

struct shim_rt_signal_queue {
    uint64_t put_idx;
    uint64_t get_idx;
    struct shim_signal* queue[MAX_SIGNAL_LOG];
};

struct shim_signal_queue {
    struct shim_signal* standard_signals[SIGRTMIN - 1];
    struct shim_rt_signal_queue rt_signal_queues[NUM_SIGS - SIGRTMIN + 1];
};

DEFINE_LIST(shim_thread);
DEFINE_LISTP(shim_thread);
struct shim_thread {
    /* Field for inserting threads on global `g_thread_list`. */
    LIST_TYPE(shim_thread) list;

    /* thread identifier */
    IDTYPE tid;

    /* credentials */
    IDTYPE uid, gid, euid, egid;

    /* thread pal handle */
    PAL_HANDLE pal_handle;

    struct shim_handle_map* handle_map;

    /* child tid */
    int* set_child_tid;
    int* clear_child_tid;    /* LibOS zeroes it to notify parent that thread exited */
    int clear_child_tid_pal; /* PAL zeroes it to notify LibOS that thread exited */

    /* signal handling */
    __sigset_t signal_mask;
    struct shim_signal_dispositions* signal_dispositions;
    struct shim_signal_queue signal_queue;
    /* For the field below, see the explanation in "LibOS/shim/src/bookkeep/shim_signal.c" near
     * `process_pending_signals_cnt`. */
    uint64_t pending_signals;

    /*
     * This field is used for checking whether we handled a signal (e.g. if we want to sleep and
     * make some decision after wakeup based on whether we handled a signal, see `sigsuspend`)
     * and can have following values:
     * - `SIGNAL_NOT_HANDLED` - usually initialized to this - no signals were handled,
     * - `SIGNAL_HANDLED` - at least one signal was handled,
     * - `SIGNAL_HANDLED_RESTART` - same as above, but the signal had `SA_RESTART` flag.
     * `SIGNAL_HANDLED` has priority over `SIGNAL_HANDLED_RESTART`, i.e. if we handle multiple
     * signals, some with `SA_RESTART`, some without it, this field will be set to `SIGNAL_HANDLED`.
     */
    unsigned char signal_handled;
    stack_t signal_altstack;

    /* futex robust list */
    struct robust_list_head* robust_list;

    PAL_HANDLE scheduler_event;

    struct wake_queue_node wake_queue;

    bool time_to_die;

    void* stack;
    void* stack_top;
    void* stack_red;
    shim_tcb_t* shim_tcb;
    void* frameptr;

    REFTYPE ref_count;
    struct shim_lock lock;
};

struct shim_thread_queue {
    struct shim_thread_queue* next;
    struct shim_thread* thread;
    /* We use this field to mark that this object is still in use (is on some queue). This is needed
     * to distinguish spurious wake-ups from real ones. */
    bool in_use;
};

/* See the explanation in `shim_thread`. */
enum {
    SIGNAL_NOT_HANDLED = 0,
    SIGNAL_HANDLED,
    SIGNAL_HANDLED_RESTART,
};

int init_threading(void);

static inline bool is_internal(struct shim_thread* thread) {
    return thread->tid >= INTERNAL_TID_BASE;
}

void clear_signal_queue(struct shim_signal_queue* queue);

void get_signal_dispositions(struct shim_signal_dispositions* dispositions);
void put_signal_dispositions(struct shim_signal_dispositions* dispositions);

void get_thread(struct shim_thread* thread);
void put_thread(struct shim_thread* thread);

void debug_setprefix(shim_tcb_t* tcb);

/* Set `debug_buf` for `tcb`. If `debug_buf` is `NULL`, then new one is allocated. If `debug_buf`
 * is not NULL, this function cannot fail. */
static inline int debug_setbuf(shim_tcb_t* tcb, struct debug_buf* debug_buf) {
    if (g_log_level <= PAL_LOG_NONE)
        return 0;

    tcb->debug_buf = debug_buf ? debug_buf : malloc(sizeof(struct debug_buf));
    if (!tcb->debug_buf) {
        return -ENOMEM;
    }

    debug_setprefix(tcb);
    return 0;
}

static inline struct shim_thread* get_cur_thread(void) {
    return SHIM_TCB_GET(tp);
}

static inline unsigned int get_cur_tid(void) {
    struct shim_thread* thread = get_cur_thread();
    if (!thread) {
        return 0;
    }
    return thread->tid;
}

static inline void set_cur_thread(struct shim_thread* thread) {
    assert(thread);

    shim_tcb_t* tcb = shim_get_tcb();

    if (thread == tcb->tp) {
        return;
    }

    get_thread(thread);
    if (tcb->tp) {
        put_thread(tcb->tp);
    }

    tcb->tp = thread;
    thread->shim_tcb = tcb;

    if (tcb->debug_buf)
        debug_setprefix(tcb);
}

static inline void thread_setwait(struct shim_thread** queue, struct shim_thread* thread) {
    if (!thread)
        thread = get_cur_thread();
    DkEventClear(thread->scheduler_event);
    if (queue) {
        get_thread(thread);
        *queue = thread;
    }
}

static inline int thread_sleep(uint64_t timeout_us) {
    struct shim_thread* cur_thread = get_cur_thread();

    if (!cur_thread)
        return -EINVAL;

    PAL_HANDLE event = cur_thread->scheduler_event;
    if (!event)
        return -EINVAL;

    if (!DkSynchronizationObjectWait(event, timeout_us))
        return -PAL_ERRNO();

    return 0;
}

static inline void thread_wakeup(struct shim_thread* thread) {
    DkEventSet(thread->scheduler_event);
}

/* Adds the thread to the wake-up queue.
 * If this thread is already on some queue, then it *will* be woken up soon and there is no need
 * to add it to another queue.
 * queue->first should be a valid pointer or WAKE_QUEUE_TAIL (i.e. cannot be NULL).
 *
 * Returns 0 if the thread was added to the queue, 1 otherwise. */
static inline int add_thread_to_queue(struct wake_queue_head* queue, struct shim_thread* thread) {
    struct wake_queue_node* nptr = NULL;
    struct wake_queue_node* qnode = &thread->wake_queue;

    /* Atomic cmpxchg is enough, no need to take thread->lock */
    if (!__atomic_compare_exchange_n(&qnode->next, &nptr, queue->first,
                                     /*weak=*/false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
        return 1;
    }

    get_thread(thread);

    queue->first = qnode;
    return 0;
}

/* Wakes up all threads on the queue.
 * This is a destructive operation - queue cannot be used after calling this function. */
static inline void wake_queue(struct wake_queue_head* queue) {
    struct wake_queue_node* qnode = queue->first;

    while (qnode != WAKE_QUEUE_TAIL) {
        struct shim_thread* thread = container_of(qnode, struct shim_thread, wake_queue);

        qnode = qnode->next;
        __atomic_store_n(&thread->wake_queue.next, NULL, __ATOMIC_RELAXED);

        thread_wakeup(thread);
        put_thread(thread);
    }
}

/*!
 * \brief Look up the thread for a given id.
 *
 * \param tid Thread id to look for.
 *
 * Searches global threads list for a thread with id equal to \p tid.
 * If no thread was found returns NULL.
 * Increases refcount of the returned thread.
 */
struct shim_thread* lookup_thread(IDTYPE tid);

struct shim_thread* get_new_thread(void);
struct shim_thread* get_new_internal_thread(void);

/* Adds `thread` to global thread list. */
void add_thread(struct shim_thread* thread);

void cleanup_thread(IDTYPE caller, void* thread);
bool check_last_thread(bool mark_self_dead);

int walk_thread_list(int (*callback)(struct shim_thread*, void*), void* arg, bool one_shot);

void get_handle_map(struct shim_handle_map* map);
void put_handle_map(struct shim_handle_map* map);

static inline struct shim_handle_map* get_thread_handle_map(struct shim_thread* thread) {
    if (!thread)
        thread = get_cur_thread();

    return thread ? thread->handle_map : NULL;
}

static inline void set_handle_map(struct shim_thread* thread, struct shim_handle_map* map) {
    get_handle_map(map);

    assert(thread);

    if (thread->handle_map)
        put_handle_map(thread->handle_map);

    thread->handle_map = map;
}

bool kill_other_threads(void);
noreturn void thread_exit(int error_code, int term_signal);
noreturn void process_exit(int error_code, int term_signal);

void release_robust_list(struct robust_list_head* head);
void release_clear_child_tid(int* clear_child_tid);

#endif /* _SHIM_THREAD_H_ */
