/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include <asm/errno.h>
#include <limits.h>
#include <linux/futex.h>
#include <linux/time.h>
#include <stdbool.h>

#include "api.h"
#include "assert.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux_error.h"

int _DkEventCreate(PAL_HANDLE* handle_ptr, bool init_signaled, bool auto_clear) {
    PAL_HANDLE handle = malloc(HANDLE_SIZE(event));
    if (!handle) {
        return -PAL_ERROR_NOMEM;
    }

    SET_HANDLE_TYPE(handle, event);
    handle->event.auto_clear = auto_clear;
    __atomic_store_n(&handle->event.signaled, init_signaled ? 1 : 0, __ATOMIC_RELEASE);

    *handle_ptr = handle;
    return 0;
}

void _DkEventSet(PAL_HANDLE handle) {
    __atomic_store_n(&handle->event.signaled, 1, __ATOMIC_RELEASE);
    int ret = INLINE_SYSCALL(futex, 6, &handle->event.signaled, FUTEX_WAKE,
                             handle->event.auto_clear ? 1 : INT_MAX, NULL, NULL, 0);
    __UNUSED(ret);
    /* This `FUTEX_WAKE` cannot really fail. */
    assert(ret >= 0);
}

void _DkEventClear(PAL_HANDLE handle) {
    __atomic_store_n(&handle->event.signaled, 0, __ATOMIC_RELEASE);
}

static int wait_timeout(PAL_HANDLE handle, int64_t timeout_us) {
    struct timespec timeout = { 0 };
    struct timespec* timeout_ptr = NULL;
    if (timeout_us >= 0) {
        timeout.tv_sec = timeout_us / TIME_US_IN_S;
        timeout.tv_nsec = (timeout_us - timeout.tv_sec * TIME_US_IN_S) * TIME_NS_IN_US;
        timeout_ptr = &timeout;
    }

    while (1) {
        bool needs_sleep = false;
        if (handle->event.auto_clear) {
            needs_sleep = __atomic_exchange_n(&handle->event.signaled, 0, __ATOMIC_ACQ_REL) == 0;
        } else {
            needs_sleep = __atomic_load_n(&handle->event.signaled, __ATOMIC_ACQUIRE) == 0;
        }

        if (!needs_sleep) {
            return 0;
        }
        /* TODO: we do not decrease timeout, so it might be off if we get woken up spuriously. */
        int ret = INLINE_SYSCALL(futex, 6, &handle->event.signaled, FUTEX_WAIT, 0, timeout_ptr,
                                 NULL, 0);
        if (ret < 0 && ret != -EAGAIN) {
            return unix_to_pal_error(ret);
        }
    }
}

struct handle_ops g_event_ops = {
    .wait = wait_timeout,
};
