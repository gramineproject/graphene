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
#include "cpu.h"
#include "linux_utils.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux_error.h"

int _DkEventCreate(PAL_HANDLE* handle_ptr, bool init_signaled, bool auto_clear) {
    PAL_HANDLE handle = malloc(HANDLE_SIZE(event));
    if (!handle) {
        return -PAL_ERROR_NOMEM;
    }

    init_handle_hdr(HANDLE_HDR(handle), PAL_TYPE_EVENT);
    handle->event.auto_clear = auto_clear;
    __atomic_store_n(&handle->event.signaled, init_signaled ? 1 : 0, __ATOMIC_RELEASE);

    *handle_ptr = handle;
    return 0;
}

void _DkEventSet(PAL_HANDLE handle) {
    __atomic_store_n(&handle->event.signaled, 1, __ATOMIC_RELEASE);
    /* We could just use `FUTEX_WAKE`, but using `FUTEX_WAKE_BITSET` is more consistent with
     * `FUTEX_WAIT_BITSET` in `_DkEventWait`. */
    int ret = DO_SYSCALL(futex, &handle->event.signaled, FUTEX_WAKE_BITSET,
                         handle->event.auto_clear ? 1 : INT_MAX, NULL, NULL,
                         FUTEX_BITSET_MATCH_ANY);
    __UNUSED(ret);
    /* This `FUTEX_WAKE_BITSET` cannot really fail. */
    assert(ret >= 0);
}

void _DkEventClear(PAL_HANDLE handle) {
    __atomic_store_n(&handle->event.signaled, 0, __ATOMIC_RELEASE);
}

int _DkEventWait(PAL_HANDLE handle, uint64_t* timeout_us) {
    int ret;
    struct timespec timeout = { 0 };
    if (timeout_us) {
        time_get_now_plus_ns(&timeout, *timeout_us * TIME_NS_IN_US);
    }

    while (1) {
        bool needs_sleep = false;
        if (handle->event.auto_clear) {
            needs_sleep = __atomic_exchange_n(&handle->event.signaled, 0, __ATOMIC_ACQ_REL) == 0;
        } else {
            needs_sleep = __atomic_load_n(&handle->event.signaled, __ATOMIC_ACQUIRE) == 0;
        }

        if (!needs_sleep) {
            ret = 0;
            break;
        }

        /* Using `FUTEX_WAIT_BITSET` to have an absolute timeout. */
        ret = DO_SYSCALL(futex, &handle->event.signaled, FUTEX_WAIT_BITSET, 0,
                         timeout_us ? &timeout : NULL, NULL, FUTEX_BITSET_MATCH_ANY);
        if (ret < 0 && ret != -EAGAIN) {
            ret = unix_to_pal_error(ret);
            break;
        }
    }

    if (timeout_us) {
        int64_t diff = time_ns_diff_from_now(&timeout);
        if (diff < 0) {
            /* We might have slept a bit too long. */
            diff = 0;
        }
        assert(ret != -PAL_ERROR_TRYAGAIN || diff == 0);
        *timeout_us = (uint64_t)diff / TIME_NS_IN_US;
    }
    return ret;
}

struct handle_ops g_event_ops = {};
