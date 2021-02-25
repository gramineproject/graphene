/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs that provide operations of (futex based) mutexes. Based on "Mutexes and
 * Condition Variables using Futexes" (http://locklessinc.com/articles/mutex_cv_futex)
 */

#include <asm/errno.h>
#include <limits.h>
#include <linux/futex.h>
#include <linux/time.h>
#include <unistd.h>

#include "api.h"
#include "atomic.h"
#include "cpu.h"
#include "pal.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"

#ifdef __x86_64__
#include <unistd.h>
#endif

#define MUTEX_SPINLOCK_TIMES 100
#define MUTEX_UNLOCKED       0
#define MUTEX_LOCKED         1

/* Interplay between locked and nwaiters:
 *
 * If lock is unlocked and uncontended, just set the locked state.
 *
 * Important possible interleavings of lock and unlock:
 *
 * Case 1:
 *
 * Owner:                Locker:
 *                       Try lock and fail; increment nwaiters; sleep
 * Set state to unlocked
 * Read nwaiters; wake
 *                       Try again and succeed.
 *
 * ***************************************************
 *
 * Case 2:
 *
 * Owner:                Locker:
 *                       Try lock and fail
 * Set state to unlocked
 * Read nwaiters (=0)
 *                      Increment nwaiters.
 *                      Can't go to sleep here; will cmpxchg locked and succeed
 * Don't wake anyone
 */

int _DkMutexCreate(PAL_HANDLE* handle, int initialCount) {
    PAL_HANDLE mut = malloc(HANDLE_SIZE(mutex));
    SET_HANDLE_TYPE(mut, mutex);
    __atomic_store_n(&mut->mutex.mut.nwaiters.counter, 0, __ATOMIC_SEQ_CST);
    mut->mutex.mut.locked = initialCount;
    *handle               = mut;
    return 0;
}

int _DkMutexLockTimeout(struct mutex_handle* m, int64_t timeout_us) {
    int i, ret = 0;
#ifdef DEBUG_MUTEX
    int tid = INLINE_SYSCALL(gettid, 0);
#endif
    /* If this is a trylock-style call, break more quickly. */
    int iterations = (timeout_us == 0) ? 1 : MUTEX_SPINLOCK_TIMES;

    /* Spin and try to take lock.  Ignore any contribution this makes toward
     * the timeout.*/
    for (i = 0; i < iterations; i++) {
        uint32_t t = MUTEX_UNLOCKED;
        if (__atomic_compare_exchange_n(&m->locked, &t, MUTEX_LOCKED, /*weak=*/true,
                                        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
            goto success;
        CPU_RELAX();
    }

    if (timeout_us == 0) {
        ret = -PAL_ERROR_TRYAGAIN;
        goto out;
    }

    // Bump up the waiters count; we are probably going to block
    __atomic_add_fetch(&m->nwaiters.counter, 1, __ATOMIC_SEQ_CST);

    while (true) {
        uint32_t t = MUTEX_UNLOCKED;
        if (__atomic_compare_exchange_n(&m->locked, &t, MUTEX_LOCKED, /*weak=*/false,
                                        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
            break;

        struct timespec waittime, *waittimep = NULL;
        if (timeout_us >= 0) {
            int64_t sec      = timeout_us / 1000000;
            int64_t microsec = timeout_us - (sec * 1000000);
            waittime.tv_sec  = sec;
            waittime.tv_nsec = microsec * 1000;
            waittimep        = &waittime;
        }

        ret = INLINE_SYSCALL(futex, 6, &m->locked, FUTEX_WAIT, MUTEX_LOCKED, waittimep, NULL, 0);

        if (IS_ERR(ret)) {
            if (ERRNO(ret) == EWOULDBLOCK) {
                if (timeout_us >= 0) {
                    ret = -PAL_ERROR_TRYAGAIN;
                    __atomic_sub_fetch(&m->nwaiters.counter, 1, __ATOMIC_SEQ_CST);
                    goto out;
                }
            } else {
#ifdef DEBUG_MUTEX
                printf("futex failed (err = %d)\n", ERRNO(ret));
#endif
                ret = unix_to_pal_error(ERRNO(ret));
                __atomic_sub_fetch(&m->nwaiters.counter, 1, __ATOMIC_SEQ_CST);
                goto out;
            }
        }
    }

    __atomic_sub_fetch(&m->nwaiters.counter, 1, __ATOMIC_SEQ_CST);

success:
#ifdef DEBUG_MUTEX
    m->owner = tid;
#endif
    ret = 0;
out:

#ifdef DEBUG_MUTEX
    if (ret < 0)
        printf("mutex failed (%s, tid = %d)\n", PAL_STRERROR(ret), tid);
#endif
    return ret;
}

int _DkMutexLock(struct mutex_handle* m) {
    return _DkMutexLockTimeout(m, -1);
}

int _DkMutexAcquireTimeout(PAL_HANDLE handle, int64_t timeout_us) {
    return _DkMutexLockTimeout(&handle->mutex.mut, timeout_us);
}

int _DkMutexUnlock(struct mutex_handle* m) {
    int ret = 0;
    int need_wake;

#ifdef DEBUG_MUTEX
    m->owner = 0;
#endif

    /* Unlock */
    __atomic_store_n(&m->locked, 0, __ATOMIC_SEQ_CST);

    need_wake = __atomic_load_n(&m->nwaiters.counter, __ATOMIC_SEQ_CST);

    /* If we need to wake someone up... */
    if (need_wake)
        INLINE_SYSCALL(futex, 6, &m->locked, FUTEX_WAKE, 1, NULL, NULL, 0);

    return ret;
}

void _DkMutexRelease(PAL_HANDLE handle) {
    _DkMutexUnlock(&handle->mutex.mut);
    return;
}

static bool _DkMutexIsLocked(struct mutex_handle* m) {
    if (!__atomic_load_n(&m->locked, __ATOMIC_SEQ_CST)) {
        return false;
    }

#ifdef DEBUG_MUTEX
    if (m->owner != INLINE_SYSCALL(gettid, 0)) {
        return false;
    }
#endif

    return true;
}

void _DkInternalLock(PAL_LOCK* lock) {
    // Retry the lock if being interrupted by signals
    while (_DkMutexLock(lock) < 0)
        ;
}

void _DkInternalUnlock(PAL_LOCK* lock) {
    _DkMutexUnlock(lock);
}

bool _DkInternalIsLocked(PAL_LOCK* lock) {
    return _DkMutexIsLocked(lock);
}

static int mutex_wait(PAL_HANDLE handle, int64_t timeout_us) {
    return _DkMutexAcquireTimeout(handle, timeout_us);
}

struct handle_ops g_mutex_ops = {
    .wait = &mutex_wait,
};
