/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

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
 * db_mutex.c
 *
 * This file contains APIs that provide operations of (futex based) mutexes.
 * Based on "Mutexes and Condition Variables using Futexes"
 * (http://locklessinc.com/articles/mutex_cv_futex)
 */

#include "pal_defs.h"
#include "pal_linux_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_error.h"
#include "api.h"

#include <linux/futex.h>
#include <limits.h>
#include <atomic.h>
#include <asm/errno.h>
#include <linux/time.h>
#include <unistd.h>

#ifdef __x86_64__
# include <unistd.h>
#endif

#define MUTEX_SPINLOCK_TIMES    100
#define MUTEX_UNLOCKED 0
#define MUTEX_LOCKED   1

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

int
_DkMutexCreate (PAL_HANDLE * handle, int initialCount)
{
    PAL_HANDLE mut = malloc(HANDLE_SIZE(mutex));
    SET_HANDLE_TYPE(mut, mutex);
    atomic_set(&mut->mutex.mut.nwaiters, 0);
    mut->mutex.mut.locked = initialCount;
    *handle = mut;
    return 0;
}

int _DkMutexLockTimeout (struct mutex_handle * m, uint64_t timeout)
{
    int i, ret = 0;
#ifdef DEBUG_MUTEX
    int tid = INLINE_SYSCALL(gettid, 0);
#endif
    /* If this is a trylock-style call, break more quickly. */
    int iterations = (timeout == 0) ? 1 : MUTEX_SPINLOCK_TIMES;

    /* Spin and try to take lock.  Ignore any contribution this makes toward
     * the timeout.*/
    for (i = 0; i < iterations; i++) {
        if (MUTEX_UNLOCKED == cmpxchg(&m->locked, MUTEX_UNLOCKED, MUTEX_LOCKED))
            goto success;
        cpu_relax();
    }

    if (timeout == 0) {
        ret = -PAL_ERROR_TRYAGAIN;
        goto out;
    }

    // Bump up the waiters count; we are probably going to block
    atomic_inc(&m->nwaiters);

    while (MUTEX_LOCKED == cmpxchg(&m->locked, MUTEX_UNLOCKED, MUTEX_LOCKED)) {
        struct timespec waittime, *waittimep = NULL;
        if (timeout != NO_TIMEOUT) {
            long sec = timeout / 1000000;
            long microsec = timeout - (sec * 1000000);
            waittime.tv_sec = sec;
            waittime.tv_nsec = microsec * 1000;
            waittimep = &waittime;
        }

        ret = INLINE_SYSCALL(futex, 6, m, FUTEX_WAIT, MUTEX_LOCKED, waittimep, NULL, 0);

        if (IS_ERR(ret)) {
            if (ERRNO(ret) == EWOULDBLOCK) {
                if (timeout != NO_TIMEOUT) {
                    ret = -PAL_ERROR_TRYAGAIN;
                    atomic_dec(&m->nwaiters);
                    goto out;
                }
            } else {
#ifdef DEBUG_MUTEX
                printf("futex failed (err = %d)\n", ERRNO(ret));
#endif
                ret = unix_to_pal_error(ERRNO(ret));
                atomic_dec(&m->nwaiters);
                goto out;
            }
        }
    }

    atomic_dec(&m->nwaiters);

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

int _DkMutexLock (struct mutex_handle * m)
{
    return _DkMutexLockTimeout(m, -1);
}

int _DkMutexAcquireTimeout (PAL_HANDLE handle, int timeout)
{
    return _DkMutexLockTimeout(&handle->mutex.mut, timeout);
}

int _DkMutexUnlock (struct mutex_handle * m)
{
    int ret = 0;
    int need_wake;

#ifdef DEBUG_MUTEX
    m->owner = 0;
#endif

    /* Unlock */
    m->locked = 0;
    /* We need to make sure the write to locked is visible to lock-ers
     * before we read the waiter count. */
    mb();

    need_wake = atomic_read(&m->nwaiters);

    /* If we need to wake someone up... */
    if (need_wake)
        INLINE_SYSCALL(futex, 6, m, FUTEX_WAKE, 1, NULL, NULL, 0);

    return ret;
}

void _DkMutexRelease (PAL_HANDLE handle)
{
    _DkMutexUnlock(&handle->mutex.mut);
    return;
}

static int mutex_wait (PAL_HANDLE handle, uint64_t timeout)
{
    return _DkMutexAcquireTimeout(handle, timeout);
}

struct handle_ops mutex_ops = {
        .wait               = &mutex_wait,
    };
