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
 * db_object.c
 *
 * This file contains APIs for closing or polling PAL handles.
 */

#include "pal_defs.h"
#include "pal_linux_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_error.h"
#include "pal_debug.h"
#include "api.h"

#include <linux/time.h>
#include <linux/poll.h>
#include <linux/wait.h>
#include <atomic.h>
#include <asm/errno.h>

#define DEFAULT_QUANTUM 500

/* internally to wait for one object. Also used as a shortcut to wait
 *  on events and semaphores.
 *
 *  Returns 0 on success, negative value on failure (e.g., -PAL_ERROR_TRYAGAIN)
 */
static int _DkObjectWaitOne (PAL_HANDLE handle, int64_t timeout)
{
    /* only for all these handle which has a file descriptor, or
       a eventfd. events and semaphores will skip this part */
    if (HANDLE_HDR(handle)->flags & HAS_FDS) {
        struct timespec timeout_ts;

        if (timeout >= 0) {
            long sec = (unsigned long) timeout / 1000000;
            long microsec = (unsigned long) timeout - (sec * 1000000);

            timeout_ts.tv_sec = sec;
            timeout_ts.tv_nsec = microsec * 1000;
        }

        struct pollfd fds[MAX_FDS];
        int off[MAX_FDS];
        int nfds = 0;
        for (int i = 0 ; i < MAX_FDS ; i++) {
            int events = 0;

            if ((HANDLE_HDR(handle)->flags & RFD(i)) &&
                !(HANDLE_HDR(handle)->flags & ERROR(i)))
                events |= POLLIN;

            if ((HANDLE_HDR(handle)->flags & WFD(i)) &&
                !(HANDLE_HDR(handle)->flags & WRITEABLE(i)) &&
                !(HANDLE_HDR(handle)->flags & ERROR(i)))
                events |= POLLOUT;

            if (events) {
                fds[nfds].fd = handle->generic.fds[i];
                fds[nfds].events = events|POLLHUP|POLLERR;
                fds[nfds].revents = 0;
                off[nfds] = i;
                nfds++;
            }
        }

        if (!nfds)
            return -PAL_ERROR_TRYAGAIN;

        int ret = INLINE_SYSCALL(ppoll, 5, &fds, nfds,
                                 timeout >= 0 ? &timeout_ts : NULL,
                                 NULL, 0);

        if (IS_ERR(ret))
            switch (ERRNO(ret)) {
                case EINTR:
                case ERESTART:
                    return -PAL_ERROR_INTERRUPTED;
                default:
                    return unix_to_pal_error(ERRNO(ret));
            }

        if (!ret)
            return -PAL_ERROR_TRYAGAIN;

        for (int i = 0 ; i < nfds ; i++) {
            if (!fds[i].revents)
                continue;
            if (fds[i].revents & POLLOUT)
                HANDLE_HDR(handle)->flags |= WRITEABLE(off[i]);
            if (fds[i].revents & (POLLHUP|POLLERR))
                HANDLE_HDR(handle)->flags |= ERROR(off[i]);
        }

        return 0;
    }

    const struct handle_ops * ops = HANDLE_OPS(handle);

    if (!ops || !ops->wait)
        return -PAL_ERROR_NOTSUPPORT;

    return ops->wait(handle, timeout);
}

/* _DkObjectsWaitAny for internal use. The function wait for any of the handle
   in the handle array. timeout can be set for the wait. */
int _DkObjectsWaitAny (int count, PAL_HANDLE * handleArray, int64_t timeout,
                       PAL_HANDLE * polled)
{
    if (count <= 0)
        return 0;

    if (count == 1) {
        // It is possible to have NULL pointers in the handle array.
        // In this case, assume nothing is polled.
        if (!handleArray[0])
            return -PAL_ERROR_TRYAGAIN;

        int rv = _DkObjectWaitOne(handleArray[0], timeout);
        if (rv == 0)
            *polled = handleArray[0];
        return rv;
    }

    int i, j, ret, maxfds = 0, nfds = 0;

    /* we are not gonna to allow any polling on muliple synchronous
       objects, doing this is simply violating the division of
       labor between PAL and library OS */
    for (i = 0 ; i < count ; i++) {
        PAL_HANDLE hdl = handleArray[i];

        if (!hdl)
            continue;

        if (!(HANDLE_HDR(hdl)->flags & HAS_FDS))
            return -PAL_ERROR_NOTSUPPORT;

        /* eliminate repeated entries */
        for (j = 0 ; j < i ; j++)
            if (hdl == handleArray[j])
                break;
        if (j == i) {
            for (j = 0 ; j < MAX_FDS ; j++)
                if (HANDLE_HDR(hdl)->flags & (RFD(j)|WFD(j)))
                    maxfds++;
        }
    }

    struct pollfd * fds = __alloca(sizeof(struct pollfd) * maxfds);
    PAL_HANDLE * hdls = __alloca(sizeof(PAL_HANDLE) * maxfds);

    for (i = 0 ; i < count ; i++) {
        PAL_HANDLE hdl = handleArray[i];

        if (!hdl)
            continue;

        for (j = 0 ; j < i ; j++)
            if (hdl == handleArray[j])
                break;
        if (j < i)
            continue;

        for (j = 0 ; j < MAX_FDS ; j++) {
            int events = 0;

            if ((HANDLE_HDR(hdl)->flags & RFD(j)) &&
                !(HANDLE_HDR(hdl)->flags & ERROR(j)))
                events |= POLLIN;

            if ((HANDLE_HDR(hdl)->flags & WFD(j)) &&
                !(HANDLE_HDR(hdl)->flags & WRITEABLE(j)) &&
                !(HANDLE_HDR(hdl)->flags & ERROR(j)))
                events |= POLLOUT;

            if (events && hdl->generic.fds[j] != PAL_IDX_POISON) {
                fds[nfds].fd = hdl->generic.fds[j];
                fds[nfds].events = events|POLLHUP|POLLERR;
                fds[nfds].revents = 0;
                hdls[nfds] = hdl;
                nfds++;
            }
        }
    }

    if (!nfds)
        return -PAL_ERROR_TRYAGAIN;

    struct timespec timeout_ts;

    if (timeout >= 0) {
        long sec = (unsigned long) timeout / 1000000;
        long microsec = (unsigned long) timeout - (sec * 1000000);
        timeout_ts.tv_sec = sec;
        timeout_ts.tv_nsec = microsec * 1000;
    }

    ret = INLINE_SYSCALL(ppoll, 5, fds, nfds,
                         timeout >= 0 ? &timeout_ts : NULL,
                         NULL, 0);

    if (IS_ERR(ret))
        switch (ERRNO(ret)) {
            case EINTR:
            case ERESTART:
                return -PAL_ERROR_INTERRUPTED;
            default:
                return unix_to_pal_error(ERRNO(ret));
        }

    if (!ret)
        return -PAL_ERROR_TRYAGAIN;

    PAL_HANDLE polled_hdl = NULL;

    for (i = 0 ; i < nfds ; i++) {
        if (!fds[i].revents)
            continue;

        PAL_HANDLE hdl = hdls[i];

        if (polled_hdl) {
            if (hdl != polled_hdl)
                continue;
        } else {
            polled_hdl = hdl;
        }

        for (j = 0 ; j < MAX_FDS ; j++)
            if ((HANDLE_HDR(hdl)->flags & (RFD(j)|WFD(j))) &&
                hdl->generic.fds[j] == fds[i].fd)
                break;

        if (j == MAX_FDS)
            continue;

        if (fds[i].revents & POLLOUT)
            HANDLE_HDR(hdl)->flags |= WRITEABLE(j);
        if (fds[i].revents & (POLLHUP|POLLERR))
            HANDLE_HDR(hdl)->flags |= ERROR(j);
    }

    *polled = polled_hdl;
    return polled_hdl ? 0 : -PAL_ERROR_TRYAGAIN;
}

#if TRACE_HEAP_LEAK == 1

PAL_HANDLE heap_alloc_head;
PAL_LOCK   heap_alloc_trace_lock = LOCK_INIT;

HEAP_ALLOC_RECORD * collect_heap_alloc_records (PAL_NUM max_records)
{
    HEAP_ALLOC_RECORD * records =
            malloc(sizeof(HEAP_ALLOC_RECORD) * max_records);

    if (!records)
        return NULL;

    memset(records, 0, sizeof(HEAP_ALLOC_RECORD) * max_records);

    _DkInternalLock(&heap_alloc_trace_lock);

    PAL_HANDLE ptr = heap_alloc_head;
    int nrecords = 0, i;

    for (; ptr ; ptr = ptr->hdr.heap_trace.next) {
        assert(!ptr->hdr.heap_trace.next ||
               ptr->hdr.heap_trace.next->hdr.heap_trace.pprev ==
               &ptr->hdr.heap_trace.next);

        for (i = 0 ; i < nrecords ; i++)
            if (ptr->hdr.heap_trace.caller == records[i].caller) {
                records[i].count++;
                break;
            }

        if (i == nrecords) {
            if (nrecords == max_records) break;
            records[nrecords].caller = ptr->hdr.heap_trace.caller;
            records[nrecords].count = 1;
            nrecords++;
        }
    }

    _DkInternalUnlock(&heap_alloc_trace_lock);

    return records;
}

#endif /* TRACE_HEAP_LEAK == 0 */
