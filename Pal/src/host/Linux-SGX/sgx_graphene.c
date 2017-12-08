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

#include <pal.h>
#include <pal_error.h>
#include <atomic.h>

#include <linux/futex.h>
#include <errno.h>

#include "sgx_internal.h"

#if 0 /* this code is useless for now */
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

                ret = INLINE_SYSCALL(futex, 6, &event->event.signaled,
                                     FUTEX_WAKE, nwaiters, NULL, NULL, 0);
                if (IS_ERR(ret))
                    atomic_set(&event->event.signaled, 0);
            }
        }
    } else {
        // Only one thread wakes up, leave unsignaled
        ret = INLINE_SYSCALL(futex, 6, &event->event.signaled, FUTEX_WAKE, 1,
                             NULL, NULL, 0);
    }

    return IS_ERR(ret) ? PAL_ERROR_TRYAGAIN : ret;
}

int _DkEventWait (PAL_HANDLE event)
{
    int ret = 0;

    if (!event->event.isnotification || !atomic_read(&event->event.signaled)) {
        atomic_inc(&event->event.nwaiters);

        do {
            ret = INLINE_SYSCALL(futex, 6, &event->event.signaled, FUTEX_WAIT,
                                  0, NULL, NULL, 0);

            if (IS_ERR(ret)) {
                if (ERRNO(ret) == EWOULDBLOCK) {
                    ret = 0;
                } else {
                    ret = -PAL_ERROR_DENIED;
                    break;
                }
            }
        } while (event->event.isnotification &&
                 !atomic_read(&event->event.signaled));

        atomic_dec(&event->event.nwaiters);
    }

    return ret;
}
#endif

#define PRINTBUF_SIZE        256

struct printbuf {
    int idx;    // current buffer index
    int cnt;    // total bytes printed so far
    char buf[PRINTBUF_SIZE];
};

static int
fputch(void * f, int ch, struct printbuf * b)
{
    b->buf[b->idx++] = ch;
    if (b->idx == PRINTBUF_SIZE - 1) {
        INLINE_SYSCALL(write, 3, 2, b->buf, b->idx);
        b->idx = 0;
    }
    b->cnt++;
    return 0;
}

static int
vprintf(const char * fmt, va_list *ap)
{
    struct printbuf b;

    b.idx = 0;
    b.cnt = 0;
    vfprintfmt((void *) &fputch, NULL, &b, fmt, ap);
    INLINE_SYSCALL(write, 3, 2, b.buf, b.idx);

    return b.cnt;
}

int
pal_printf(const char * fmt, ...)
{
    va_list ap;
    int cnt;

    va_start(ap, fmt);
    cnt = vprintf(fmt, &ap);
    va_end(ap);

    return cnt;
}
