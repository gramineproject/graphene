/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs that provide operations of (futex based) mutexes. Based on "Mutexes and
 * Condition Variables using Futexes" (http://locklessinc.com/articles/mutex_cv_futex)
 */

#include <asm/errno.h>
#include <errno.h>
#include <limits.h>
#include <linux/futex.h>
#include <linux/time.h>

#include "api.h"
#include "atomic.h"
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
    __atomic_store_n(&mut->mutex.mut.nwaiters.counter, 0, __ATOMIC_SEQ_CST);
    mut->mutex.mut.locked = malloc_untrusted(sizeof(uint32_t));
    if (!mut->mutex.mut.locked) {
        free(mut);
        return -PAL_ERROR_NOMEM;
    }
    *handle                  = mut;
    __atomic_store_n(mut->mutex.mut.locked, initialCount, __ATOMIC_SEQ_CST);
    return 0;
}

int _DkMutexLockTimeout(struct mutex_handle* m, int64_t timeout_us) {
    int ret = 0;

    uint32_t t = MUTEX_UNLOCKED;
    if (__atomic_compare_exchange_n(m->locked, &t, MUTEX_LOCKED, /*weak=*/false, __ATOMIC_ACQUIRE,
                                    __ATOMIC_RELAXED))
        goto success;

    if (timeout_us == 0) {
        ret = -PAL_ERROR_TRYAGAIN;
        goto out;
    }

    // Bump up the waiters count; we are probably going to block
    __atomic_add_fetch(&m->nwaiters.counter, 1, __ATOMIC_SEQ_CST);

    while (true) {
        uint32_t t = MUTEX_UNLOCKED;
        if (__atomic_compare_exchange_n(m->locked, &t, MUTEX_LOCKED, /*weak=*/false,
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
            } else {
                ret = unix_to_pal_error(ERRNO(ret));
            }
            __atomic_sub_fetch(&m->nwaiters.counter, 1, __ATOMIC_SEQ_CST);
            goto out;
        }
    }

    __atomic_sub_fetch(&m->nwaiters.counter, 1, __ATOMIC_SEQ_CST);

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
    __atomic_store_n(m->locked, MUTEX_UNLOCKED, __ATOMIC_SEQ_CST);

    need_wake = __atomic_load_n(&m->nwaiters.counter, __ATOMIC_SEQ_CST);

    /* If we need to wake someone up... */
    if (need_wake)
        ocall_futex(m->locked, FUTEX_WAKE, 1, -1);

    return ret;
}

void _DkMutexRelease(PAL_HANDLE handle) {
    struct mutex_handle* mut = &handle->mutex.mut;
    int ret = _DkMutexUnlock(mut);
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

struct handle_ops g_mutex_ops = {
    .wait  = &mutex_wait,
    .close = &mutex_close,
};
