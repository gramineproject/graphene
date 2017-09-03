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
#include "pal_linux_error.h"
#include "pal_error.h"
#include "pal_debug.h"
#include "api.h"

#include <linux/futex.h>
#include <limits.h>
#include <atomic.h>
#include <linux/time.h>
#include <errno.h>
#include <asm/errno.h>

#define MUTEX_SPINLOCK_TIMES    100
#define MUTEX_UNLOCKED            0
#define MUTEX_LOCKED              1


int
_DkMutexCreate (PAL_HANDLE handle, int initialCount)
{
    /*
     * Allocation and free of the handle are done outside of host-specific code.
     * This code initializes the mutex state that is host-specific,
     * including how initialCount is encoded.
     */
    SET_HANDLE_TYPE(handle, mutex);
    atomic_set(&handle->mutex.mut.nwaiters, 0);
    handle->mutex.mut.locked = initialCount;
    return 0;
}

void _DkMutexDestroy (PAL_HANDLE handle)
{
    free(handle);
}


int _DkMutexLockTimeout (struct mutex_handle * m, uint64_t timeout)
{
    int ret = 0;
#ifdef DEBUG_MUTEX
    int tid = INLINE_SYSCALL(gettid, 0);
#endif

    if (MUTEX_UNLOCKED == cmpxchg(&m->locked, MUTEX_UNLOCKED, MUTEX_LOCKED))
        goto success;

    if (timeout == 0) {
        ret = -PAL_ERROR_TRYAGAIN;
        goto out;
    }

    // Bump up the waiters count; we are probably going to block
    atomic_inc(&m->nwaiters);

    while (MUTEX_LOCKED == cmpxchg(&m->locked, MUTEX_UNLOCKED, MUTEX_LOCKED)) {

        // This is broken. The mutex is in enclave memory, the URTS can't
        // do FUTEX_WAIT on it. This call will always fail and the next level
        // up needs to retry.
        ret = ocall_futex((int *) m, FUTEX_WAIT, MUTEX_LOCKED, timeout == -1 ? NULL : &timeout);

        if (ret < 0) {
            if (-ret == EWOULDBLOCK) {
                ret = -PAL_ERROR_TRYAGAIN;
                atomic_dec(&m->nwaiters);
                goto out;
            }
#ifdef DEBUG_MUTEX
            printf("futex failed (err = %d)\n", ERRNO(ret));
#endif
            ret = unix_to_pal_error(ERRNO(ret));
            atomic_dec(&m->nwaiters);
            goto out;
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
    int ret = 0, i;
#ifdef DEBUG_MUTEX
    int tid = INLINE_SYSCALL(gettid, 0);
#endif
    return _DkMutexLockTimeout(m, -1);
}

int _DkMutexAcquireTimeout (PAL_HANDLE handle, int _timeout)
{
    struct mutex_handle * mut = &handle->mutex.mut;
    return _DkMutexLockTimeout(mut, _timeout);
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

    need_wake= atomic_read(&m->nwaiters);
    
    /* If we need to wake someone up... */
    if (need_wake)
        ocall_futex((int *) m, FUTEX_WAKE, 1, NULL);
    
    return ret;
}

void _DkMutexRelease (PAL_HANDLE handle) {
    struct mutex_handle * mut =
        &handle->mutex.mut;

    int ret = _DkMutexUnlock(mut);
    if (ret < 0)
        _DkRaiseFailure(ret);
    return;
}

