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
 * db_event.c
 *
 * This file contains implementation of Drawbridge event synchronization APIs.
 */

#include "pal_defs.h"
#include "pal_linux_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_error.h"
#include "api.h"

#include <atomic.h>
#include <linux/futex.h>
#include <linux/time.h>

int _DkEventCreate (PAL_HANDLE * event, bool initialState, bool isnotification)
{
    PAL_HANDLE ev = malloc_untrusted(HANDLE_SIZE(event));
    SET_HANDLE_TYPE(ev, event);
    ev->event.isnotification = isnotification;
    atomic_set(&ev->event.signaled, initialState ? 1 : 0);
    atomic_set(&ev->event.nwaiters, 0);
    *event = ev;
    return 0;
}

void _DkEventDestroy (PAL_HANDLE handle)
{
    free_untrusted(handle);
}

int _DkEventSet (PAL_HANDLE event, int wakeup)
{
    int ret = 0;

    if (event->event.isnotification) {
        // Leave it signaled, wake all
        if (atomic_cmpxchg(&event->event.signaled, 0, 1) == 0) {
            int nwaiters = atomic_read(&event->event.nwaiters);
            if (nwaiters) {
                if (wakeup != -1 && nwaiters > wakeup)
                    nwaiters = wakeup;

                ret = ocall_futex((int *) &event->event.signaled.counter,
                                  FUTEX_WAKE, nwaiters, NULL);

                if (ret < 0)
                    atomic_set(&event->event.signaled, 0);
            }
        }
    } else {
        // Only one thread wakes up, leave unsignaled
        ret = ocall_futex((int *) &event->event.signaled.counter,
                          FUTEX_WAKE, 1, NULL);
        if (ret < 0)
             return ret;
    }

    return ret;
}

int _DkEventWaitTimeout (PAL_HANDLE event, uint64_t timeout)
{
    int ret = 0;

    if (!event->event.isnotification || !atomic_read(&event->event.signaled)) {
        unsigned long waittime = timeout;

        atomic_inc(&event->event.nwaiters);

        do {
            ret = ocall_futex((int *) &event->event.signaled.counter,
                              FUTEX_WAIT, 0, timeout ? &waittime : NULL);
            if (ret < 0) {
                if (ret == -PAL_ERROR_TRYAGAIN)
                    ret = 0;
                else
                    break;
            }
        } while (event->event.isnotification &&
                 !atomic_read(&event->event.signaled));

        atomic_dec(&event->event.nwaiters);
    }

    return ret;
}

int _DkEventWait (PAL_HANDLE event)
{
    int ret = 0;

    if (!event->event.isnotification || !atomic_read(&event->event.signaled)) {
        atomic_inc(&event->event.nwaiters);

        do {
            ret = ocall_futex((int *) &event->event.signaled.counter,
                              FUTEX_WAIT, 0, NULL);
            if (ret < 0) {
                if (ret == -PAL_ERROR_TRYAGAIN)
                    ret = 0;
                else
                    break;
            }
        } while (event->event.isnotification &&
                 !atomic_read(&event->event.signaled));

        atomic_dec(&event->event.nwaiters);
    }

    return ret;
}

int _DkEventClear (PAL_HANDLE event)
{
    atomic_set(&event->event.signaled, 0);
    return 0;
}
