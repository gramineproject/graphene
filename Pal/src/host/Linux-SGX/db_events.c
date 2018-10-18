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
 * db_event.c
 *
 * This file contains implementation of Drawbridge event synchronization APIs.
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

#include <atomic.h>
#include <linux/futex.h>
#include <linux/time.h>

int _DkEventCreate (PAL_HANDLE * event, bool initialState, bool isnotification)
{
    PAL_HANDLE ev = malloc(HANDLE_SIZE(event));
    SET_HANDLE_TYPE(ev, event);
    ev->event.isnotification = isnotification;
    ev->event.signaled = malloc_untrusted(sizeof(struct atomic_int));
    if (!ev->event.signaled) {
        free(ev);
        return -PAL_ERROR_NOMEM;
    }
    atomic_set(ev->event.signaled, initialState ? 1 : 0);
    atomic_set(&ev->event.nwaiters, 0);
    *event = ev;
    return 0;
}

int _DkEventSet (PAL_HANDLE event, int wakeup)
{
    int ret = 0;

    if (event->event.isnotification) {
        // Leave it signaled, wake all
        if (atomic_cmpxchg(event->event.signaled, 0, 1) == 0) {
            int nwaiters = atomic_read(&event->event.nwaiters);
            if (nwaiters) {
                if (wakeup != -1 && nwaiters > wakeup)
                    nwaiters = wakeup;

                ret = ocall_futex((int *) &event->event.signaled->counter,
                                  FUTEX_WAKE, nwaiters, NULL);

                if (IS_ERR(ret)) {
                    atomic_set(event->event.signaled, 0);
                    ret = unix_to_pal_error(ERRNO(ret));
                }
            }
        }
    } else {
        // Only one thread wakes up, leave unsignaled
        ret = ocall_futex((int *) &event->event.signaled->counter,
                          FUTEX_WAKE, 1, NULL);
        if (IS_ERR(ret))
            return unix_to_pal_error(ERRNO(ret));
    }

    return ret;
}

int _DkEventWaitTimeout (PAL_HANDLE event, PAL_NUM timeout)
{
    int ret = 0;

    if (!event->event.isnotification || !atomic_read(event->event.signaled)) {
        int64_t waittime = timeout;

        atomic_inc(&event->event.nwaiters);

        do {
            ret = ocall_futex((int *) &event->event.signaled->counter,
                              FUTEX_WAIT, 0, timeout != NO_TIMEOUT ? &waittime : NULL);
            if (IS_ERR(ret)) {
                if (ERRNO(ret) == EWOULDBLOCK) {
                    ret = 0;
                } else {
                    ret = unix_to_pal_error(ERRNO(ret));
                    break;
                }
            }
        } while (event->event.isnotification &&
                 !atomic_read(event->event.signaled));

        atomic_dec(&event->event.nwaiters);
    }

    return ret;
}

int _DkEventWait (PAL_HANDLE event)
{
    int ret = 0;

    if (!event->event.isnotification || !atomic_read(event->event.signaled)) {
        atomic_inc(&event->event.nwaiters);

        do {
            ret = ocall_futex((int *) &event->event.signaled->counter,
                              FUTEX_WAIT, 0, NULL);
            if (IS_ERR(ret)) {
                if (ERRNO(ret) == EWOULDBLOCK) {
                    ret = 0;
                } else {
                    ret = unix_to_pal_error(ERRNO(ret));
                    break;
                }
            }
        } while (event->event.isnotification &&
                 !atomic_read(event->event.signaled));

        atomic_dec(&event->event.nwaiters);
    }

    return ret;
}

int _DkEventClear (PAL_HANDLE event)
{
    atomic_set(event->event.signaled, 0);
    return 0;
}

static int event_close (PAL_HANDLE handle)
{
    _DkEventSet(handle, -1);
    free_untrusted(handle->event.signaled);
    return 0;
}

static int event_wait (PAL_HANDLE handle, PAL_NUM timeout)
{
    return timeout == NO_TIMEOUT ? _DkEventWait(handle) :
           _DkEventWaitTimeout(handle, timeout);
}

struct handle_ops event_ops = {
        .close              = &event_close,
        .wait               = &event_wait,
    };
