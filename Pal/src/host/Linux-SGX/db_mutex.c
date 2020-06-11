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

#include <asm/errno.h>
#include <atomic.h>
#include <errno.h>
#include <limits.h>
#include <linux/futex.h>
#include <linux/time.h>

#include "api.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_linux_error.h"

#define MUTEX_SPINLOCK_TIMES 100
#define MUTEX_UNLOCKED       0
#define MUTEX_LOCKED         1

int _DkMutexCreate(PAL_HANDLE* handle, int initialCount) {
    PAL_HANDLE mut = malloc(HANDLE_SIZE(mutex));
    SET_HANDLE_TYPE(mut, mutex);
    atomic_set(&mut->mutex.mut.nwaiters, 0);
    mut->mutex.mut.locked = malloc_untrusted(sizeof(uint32_t));
    if (!mut->mutex.mut.locked) {
        free(mut);
        return -PAL_ERROR_NOMEM;
    }
    *(mut->mutex.mut.locked) = initialCount;
    *handle                  = mut;
    return 0;
}

int _DkMutexLockTimeout(struct mutex_handle* m, int64_t timeout_us) {
    int ret = 0;

    uint32_t t = MUTEX_UNLOCKED;
    if (__atomic_compare_exchange_n(&m->locked, &t, MUTEX_LOCKED, /*weak=*/true,
                                    __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
        goto success;

    if (timeout_us == 0) {
        ret = -PAL_ERROR_TRYAGAIN;
        goto out;
    }

    // Bump up the waiters count; we are probably going to block
    atomic_inc(&m->nwaiters);

    while (true) {
        uint32_t t = MUTEX_UNLOCKED;
        if (__atomic_compare_exchange_n(&m->locked, &t, MUTEX_LOCKED, /*weak=*/true,
                                        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
            break;
        /*
         * Chia-Che 12/7/2017: m->locked points to untrusted memory, so
         * can be used for futex. Potentially this design may allow
         * attackers to change the mutex value and cause DoS.
         */
        ret = ocall_futex(m->locked, FUTEX_WAIT, MUTEX_LOCKED, timeout_us);

        if (IS_ERR(ret)) {
            if (ERRNO(ret) == EWOULDBLOCK) {
                ret = -PAL_ERROR_TRYAGAIN;
                atomic_dec(&m->nwaiters);
            } else {
                ret = unix_to_pal_error(ERRNO(ret));
                atomic_dec(&m->nwaiters);
            }
            goto out;
        }
    }

    atomic_dec(&m->nwaiters);

success:
    ret = 0;
out:
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

    /* Unlock */
    __atomic_store_n(m->locked, MUTEX_UNLOCKED, __ATOMIC_RELEASE);

    need_wake = atomic_read(&m->nwaiters);

    /* If we need to wake someone up... */
    if (need_wake)
        ocall_futex(m->locked, FUTEX_WAKE, 1, -1);

    return ret;
}

void _DkMutexRelease(PAL_HANDLE handle) {
    struct mutex_handle* mut = &handle->mutex.mut;
    int ret                  = _DkMutexUnlock(mut);
    if (ret < 0)
        _DkRaiseFailure(ret);
    return;
}

static int mutex_wait(PAL_HANDLE handle, int64_t timeout_us) {
    return _DkMutexAcquireTimeout(handle, timeout_us);
}

static int mutex_close(PAL_HANDLE handle) {
    free_untrusted((int64_t*)handle->mutex.mut.locked);
    return 0;
}

struct handle_ops mutex_ops = {
    .wait  = &mutex_wait,
    .close = &mutex_close,
};
