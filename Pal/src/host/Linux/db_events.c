/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * db_event.c
 *
 * This file contains implementation of Drawbridge event synchronization APIs.
 */

#include <asm/errno.h>
#include <atomic.h>
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

int _DkEventCreate(PAL_HANDLE* event, bool initialState, bool isnotification) {
    PAL_HANDLE ev = malloc(HANDLE_SIZE(event));
    SET_HANDLE_TYPE(ev, event);
    ev->event.isnotification = isnotification;
    __atomic_store_n(&ev->event.nwaiters.counter, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&ev->event.signaled, initialState ? 1 : 0, __ATOMIC_SEQ_CST);
    *event = ev;
    return 0;
}

int _DkEventSet(PAL_HANDLE event, int wakeup) {
    int ret = 0;

    if (event->event.isnotification) {
        // Leave it signaled, wake all
        uint32_t t = 0;
        if (__atomic_compare_exchange_n(&event->event.signaled, &t, 1, /*weak=*/false,
                                        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            int nwaiters = __atomic_load_n(&event->event.nwaiters.counter, __ATOMIC_SEQ_CST);
            if (nwaiters) {
                if (wakeup != -1 && nwaiters > wakeup)
                    nwaiters = wakeup;

                ret = INLINE_SYSCALL(futex, 6, &event->event.signaled, FUTEX_WAKE, nwaiters, NULL,
                                     NULL, 0);
                if (IS_ERR(ret))
                    __atomic_store_n(&event->event.signaled, 0, __ATOMIC_SEQ_CST);
            }
        }
    } else {
        // Only one thread wakes up, leave unsignaled
        ret = INLINE_SYSCALL(futex, 6, &event->event.signaled, FUTEX_WAKE, 1, NULL, NULL, 0);
    }

    return IS_ERR(ret) ? -PAL_ERROR_TRYAGAIN : ret;
}

int _DkEventWaitTimeout(PAL_HANDLE event, int64_t timeout_us) {
    int ret = 0;

    if (timeout_us < 0)
        return _DkEventWait(event);

    if (!event->event.isnotification ||
        !__atomic_load_n(&event->event.signaled, __ATOMIC_SEQ_CST)) {
        struct timespec waittime;
        int64_t sec      = timeout_us / 1000000UL;
        int64_t microsec = timeout_us - (sec * 1000000UL);
        waittime.tv_sec  = sec;
        waittime.tv_nsec = microsec * 1000;

        __atomic_add_fetch(&event->event.nwaiters.counter, 1, __ATOMIC_SEQ_CST);

        do {
            ret =
                INLINE_SYSCALL(futex, 6, &event->event.signaled, FUTEX_WAIT, 0, &waittime, NULL, 0);

            if (IS_ERR(ret)) {
                if (ERRNO(ret) == EWOULDBLOCK) {
                    ret = 0;
                } else {
                    ret = unix_to_pal_error(ERRNO(ret));
                    break;
                }
            }
        } while (event->event.isnotification &&
                 !__atomic_load_n(&event->event.signaled, __ATOMIC_SEQ_CST));

        __atomic_sub_fetch(&event->event.nwaiters.counter, 1, __ATOMIC_SEQ_CST);
    }

    return ret;
}

int _DkEventWait(PAL_HANDLE event) {
    int ret = 0;

    if (!event->event.isnotification ||
        !__atomic_load_n(&event->event.signaled, __ATOMIC_SEQ_CST)) {

        __atomic_add_fetch(&event->event.nwaiters.counter, 1, __ATOMIC_SEQ_CST);

        do {
            ret = INLINE_SYSCALL(futex, 6, &event->event.signaled, FUTEX_WAIT, 0, NULL, NULL, 0);

            if (IS_ERR(ret)) {
                if (ERRNO(ret) == EWOULDBLOCK) {
                    ret = 0;
                } else {
                    ret = unix_to_pal_error(ERRNO(ret));
                    break;
                }
            }
        } while (event->event.isnotification &&
                 !__atomic_load_n(&event->event.signaled, __ATOMIC_SEQ_CST));

        __atomic_sub_fetch(&event->event.nwaiters.counter, 1, __ATOMIC_SEQ_CST);
    }

    return ret;
}

int _DkEventClear(PAL_HANDLE event) {
    __atomic_store_n(&event->event.signaled, 0, __ATOMIC_SEQ_CST);
    return 0;
}

static int event_close(PAL_HANDLE handle) {
    _DkEventSet(handle, -1);
    return 0;
}

static int event_wait(PAL_HANDLE handle, int64_t timeout_us) {
    return _DkEventWaitTimeout(handle, timeout_us);
}

struct handle_ops g_event_ops = {
    .close = &event_close,
    .wait  = &event_wait,
};
