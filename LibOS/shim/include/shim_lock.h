/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#ifndef _SHIM_LOCK_H_
#define _SHIM_LOCK_H_

#include <stdbool.h>

#include "assert.h"
#include "pal.h"
#include "pal_debug.h"
#include "shim_internal.h"
#include "shim_tcb.h"
#include "shim_thread.h"
#include "shim_types.h"

extern bool lock_enabled;

static inline void enable_locking(void) {
    if (!lock_enabled)
        lock_enabled = true;
}

static inline bool lock_created(struct shim_lock* l) {
    return l->lock != NULL;
}

static inline void clear_lock(struct shim_lock* l) {
    l->lock  = NULL;
    l->owner = 0;
}

static inline bool create_lock(struct shim_lock* l) {
    l->owner = 0;
    l->lock  = DkMutexCreate(0);
    return l->lock != NULL;
}

static inline void destroy_lock(struct shim_lock* l) {
    DkObjectClose(l->lock);
    clear_lock(l);
}

#ifdef DEBUG
#define lock(l) __lock(l, __FILE__, __LINE__)
static void __lock(struct shim_lock* l, const char* file, int line) {
#else
static void lock(struct shim_lock* l) {
#endif
    if (!lock_enabled) {
        return;
    }
    /* TODO: This whole if should be just an assert. Change it once we are sure that it does not
     * trigger (previous code allowed for this case). Same in unlock below. */
    if (!l->lock) {
#ifdef DEBUG
        debug("Trying to lock an uninitialized lock at %s:%d!\n", file, line);
#endif // DEBUG
        __abort();
    }

    shim_tcb_t* tcb = shim_get_tcb();
    disable_preempt(tcb);

    while (!DkSynchronizationObjectWait(l->lock, NO_TIMEOUT))
        /* nop */;

    l->owner = get_cur_tid();
}

#ifdef DEBUG
#define unlock(l) __unlock(l, __FILE__, __LINE__)
static inline void __unlock(struct shim_lock* l, const char* file, int line) {
#else
static inline void unlock(struct shim_lock* l) {
#endif
    if (!lock_enabled) {
        return;
    }
    if (!l->lock) {
#ifdef DEBUG
        debug("Trying to unlock an uninitialized lock at %s:%d!\n", file, line);
#endif // DEBUG
        __abort();
    }

    shim_tcb_t* tcb = shim_get_tcb();

    l->owner = 0;
    DkMutexRelease(l->lock);
    enable_preempt(tcb);
}

static inline bool locked(struct shim_lock* l) {
    if (!lock_enabled) {
        return true;
    }
    if (!l->lock) {
        return false;
    }
    return get_cur_tid() == l->owner;
}

#define DEBUG_MASTER_LOCK 0

extern struct shim_lock __master_lock;

#if DEBUG_MASTER_LOCK == 1
#define MASTER_LOCK()                                          \
    do {                                                       \
        lock(&__master_lock);                                  \
        pal_printf("master lock " __FILE__ ":%d\n", __LINE__); \
    } while (0)
#define MASTER_UNLOCK()                                          \
    do {                                                         \
        pal_printf("master unlock " __FILE__ ":%d\n", __LINE__); \
        unlock(&__master_lock);                                  \
    } while (0)
#else
#define MASTER_LOCK()         \
    do {                      \
        lock(&__master_lock); \
    } while (0)
#define MASTER_UNLOCK()         \
    do {                        \
        unlock(&__master_lock); \
    } while (0)
#endif

static inline bool create_lock_runtime(struct shim_lock* l) {
    bool ret = true;

    if (!lock_created(l)) {
        MASTER_LOCK();
        if (!lock_created(l))
            ret = create_lock(l);
        MASTER_UNLOCK();
    }

    return ret;
}

#endif // _SHIM_LOCK_H_
