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
 * db_semaphore.c
 *
 * This file contains APIs that provides operations of semaphores.
 */

#include "pal_defs.h"
#include "pal_linux_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_error.h"
#include "api.h"

#include <cmpxchg.h>
#include <atomic.h>
#include <linux/futex.h>
#include <limits.h>
#include <linux/time.h>

static inline int atomic_dec_if_positive (struct atomic_int *v)
{
    int c, old, dec;
    c = atomic_read(v);
    for (;;) {
        dec = c - 1;
        if (dec < 0)
            break;
        old = atomic_cmpxchg((v), c, dec);
        if (old == c)
            break;
        c = old;
    }
    return dec;
}

int
_DkSemaphoreCreate (PAL_HANDLE handle, int initialCount, int maxCount)
{
    /*
     * 1. Allocate memory for db_sem (this includes a futex variable).
     * 2. Pack it into a PAL_HANDLE
     * 3. Set the semaphore object with the argument values (count, maxCount)
     */

    SET_HANDLE_TYPE(handle, semaphore);
    atomic_set(&handle->semaphore.nwaiters, 0);
    handle->semaphore.max_value = maxCount;

    /* optimization: if maxCount == 1, we make it into mutex */
    if (handle->semaphore.max_value == 1) {
        atomic_set(&handle->semaphore.value.mut.value, 1 - initialCount);
    } else {
        atomic_set(&handle->semaphore.value.i, maxCount - initialCount);
    }

    return 0;
}

void _DkSemaphoreDestroy (PAL_HANDLE semaphoreHandle)
{
    /* do nothing */
}

int _DkMutexLockTimeout (struct mutex_handle * mut, int timeout);

int _DkSemaphoreAcquire (PAL_HANDLE sem, int count)
{
    /* optimization: use it as a mutex */
    if (sem->semaphore.max_value == 1) {
        struct mutex_handle * mut = &sem->semaphore.value.mut;
        _DkMutexLock(mut);
        return 0;
    }

    if (count > sem->semaphore.max_value)
        return -PAL_ERROR_INVAL;

    struct atomic_int * value = &sem->semaphore.value.i;
    int c = 0;

    if (!value)
        return -PAL_ERROR_BADHANDLE;

    if (count == 1)
        c = atomic_dec_and_test_nonnegative (value);
    else
        c = atomic_sub_and_test_nonnegative (count, value);

    if (c)
        return 0;

    /* We didn't get the lock.  Bump the count back up. */
    if (count == 1)
        atomic_inc (value);
    else
        atomic_add (count, value);

    int ret = 0;
    atomic_inc (&sem->semaphore.nwaiters);

    while (1) {
        ret = ocall_futex((int *) &value->counter, FUTEX_WAIT, 0, NULL);

        if (ret < 0) {
            if (ret == -PAL_ERROR_TRYAGAIN)
                ret = 0;
            else
                break;
        }

        if (count == 1)
            c = atomic_dec_and_test_nonnegative (value);
        else
            c = atomic_sub_and_test_nonnegative (count, value);

        if (c)
            break;

        /* We didn't get the lock.  Bump the count back up. */
        if (count == 1)
            atomic_inc (value);
        else
            atomic_add (count, value);
    }

    atomic_dec (&sem->semaphore.nwaiters);
    return ret;
}

int _DkSemaphoreAcquireTimeout (PAL_HANDLE sem, int count, int timeout)
{
    /* Pass it up to the no-timeout version if no timeout requested */
    if (timeout == -1)
        return _DkSemaphoreAcquire(sem, count);

    /* optimization: use it as a mutex */
    if (sem->semaphore.max_value == 1) {
        struct mutex_handle * mut = & sem->semaphore.value.mut;
        _DkMutexLockTimeout(mut, timeout);
        return 0;
    }

    if (count > sem->semaphore.max_value)
        return -PAL_ERROR_INVAL;

    struct atomic_int * value = &sem->semaphore.value.i;
    int c = 0;

    if (!value)
        return -PAL_ERROR_BADHANDLE;

    if (count == 1)
        c = atomic_dec_and_test_nonnegative (value);
    else
        c = atomic_sub_and_test_nonnegative (count, value);

    if (c)
        return 0;

    /* We didn't get the lock.  Bump the count back up. */
    if (count == 1)
        atomic_inc ((struct atomic_int *) value);
    else
        atomic_add (count, (struct atomic_int *) value);

    if (!timeout)
        return 0;

    unsigned long waittime = timeout;
    int ret = 0;

    atomic_inc (&sem->semaphore.nwaiters);

    while (1) {
        ret = ocall_futex((int *) &value->counter, FUTEX_WAIT, 0, timeout >= 0 ? &waittime : NULL);

        if (ret < 0) {
            if (ret == -PAL_ERROR_TRYAGAIN)
                ret = 0;
            else
                break;
        }

        if (count == 1)
            c = atomic_dec_and_test_nonnegative (value);
        else
            c = atomic_sub_and_test_nonnegative (count, value);

        if (c)
            break;
    }

    /* We didn't get the lock.  Bump the count back up. */
    if (count == 1)
        atomic_inc (value);
    else
        atomic_add (count, value);

    atomic_dec (&sem->semaphore.nwaiters);
    return ret;
}

void _DkSemaphoreRelease (PAL_HANDLE sem, int count)
{
    /* optimization: use it as a mutex */
    if (sem->semaphore.max_value == 1) {
        struct mutex_handle * mut =
            &sem->semaphore.value.mut;

        _DkMutexUnlock(mut);
        return;
    }

    struct atomic_int * value = &sem->semaphore.value.i;

    if (count == 1)
        atomic_inc (value);
    else
        atomic_add (count, value);

    int nwaiters = atomic_read (&sem->semaphore.nwaiters);
    if (nwaiters > 0)
        ocall_futex((int *) &value->counter, FUTEX_WAKE, nwaiters, NULL);
}

int _DkSemaphoreGetCurrentCount (PAL_HANDLE sem)
{
    if (sem->semaphore.max_value == 1) {
        struct mutex_handle * mut =
            &sem->semaphore.value.mut;
        return atomic_read(&mut->value);
    }

    int c = atomic_read(&sem->semaphore.value.i);
    return sem->semaphore.max_value - c;
}
