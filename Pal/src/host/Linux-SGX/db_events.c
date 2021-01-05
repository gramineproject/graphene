/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains implementation of Drawbridge event synchronization APIs.
 */

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

int _DkEventCreate(PAL_HANDLE* event, bool initialState, bool isnotification) {
    PAL_HANDLE ev = malloc(HANDLE_SIZE(event));
    SET_HANDLE_TYPE(ev, event);
    ev->event.isnotification = isnotification;
    ev->event.signaled       = malloc_untrusted(sizeof(uint32_t));
    if (!ev->event.signaled) {
        free(ev);
        return -PAL_ERROR_NOMEM;
    }
    __atomic_store_n(&ev->event.nwaiters.counter, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(ev->event.signaled, initialState ? 1 : 0, __ATOMIC_SEQ_CST);
    *event = ev;
    return 0;
}

int _DkEventSet(PAL_HANDLE event, int wakeup) {
    int ret = 0;

    if (event->event.isnotification) {
        // Leave it signaled, wake all
        uint32_t t = 0;
        if (__atomic_compare_exchange_n(event->event.signaled, &t, 1, /*weak=*/false,
                                        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            int nwaiters = __atomic_load_n(&event->event.nwaiters.counter, __ATOMIC_SEQ_CST);
            if (nwaiters) {
                if (wakeup != -1 && nwaiters > wakeup)
                    nwaiters = wakeup;

                ret = ocall_futex(event->event.signaled, FUTEX_WAKE, nwaiters, -1);

                if (IS_ERR(ret)) {
                    __atomic_store_n(event->event.signaled, 0, __ATOMIC_SEQ_CST);
                    ret = unix_to_pal_error(ERRNO(ret));
                }
            }
        }
    } else {
        // Only one thread wakes up, leave unsignaled
        ret = ocall_futex(event->event.signaled, FUTEX_WAKE, 1, -1);
        if (IS_ERR(ret))
            return unix_to_pal_error(ERRNO(ret));
    }

    return ret;
}

int _DkEventWaitTimeout(PAL_HANDLE event, int64_t timeout_us) {
    int ret = 0;

    if (timeout_us < 0) {
        timeout_us = -1;
    }

    if (!event->event.isnotification || !__atomic_load_n(event->event.signaled, __ATOMIC_SEQ_CST)) {
        __atomic_add_fetch(&event->event.nwaiters.counter, 1, __ATOMIC_SEQ_CST);

        do {
            ret = ocall_futex(event->event.signaled, FUTEX_WAIT, 0, timeout_us);

            if (ret < 0) {
                if (ret == -EWOULDBLOCK) {
                    ret = 0;
                } else if (ret == -EINTR
                           && (!event->event.isnotification
                               || __atomic_load_n(&event->event.signaled, __ATOMIC_SEQ_CST))) {
                    ret = 0;
                    break;
                } else {
                    ret = unix_to_pal_error(-ret);
                    break;
                }
            }
        } while (event->event.isnotification &&
                 !__atomic_load_n(event->event.signaled, __ATOMIC_SEQ_CST));

        __atomic_sub_fetch(&event->event.nwaiters.counter, 1, __ATOMIC_SEQ_CST);
    }

    return ret;
}

int _DkEventClear(PAL_HANDLE event) {
    __atomic_store_n(event->event.signaled, 0, __ATOMIC_SEQ_CST);
    return 0;
}

static int event_close(PAL_HANDLE handle) {
    _DkEventSet(handle, -1);
    free_untrusted(handle->event.signaled);
    return 0;
}

static int event_wait(PAL_HANDLE handle, int64_t timeout_us) {
    return _DkEventWaitTimeout(handle, timeout_us);
}

struct handle_ops g_event_ops = {
    .close = &event_close,
    .wait  = &event_wait,
};
