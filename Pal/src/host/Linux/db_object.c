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
 * This file contains APIs for waiting on PAL handles (polling).
 */

#include "api.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"

#include <asm/errno.h>
#include <linux/poll.h>
#include <linux/time.h>
#include <linux/wait.h>

/* Wait for an event on any handle in the handle array and return this handle in polled.
 * If no ready-event handle was found, polled is set to NULL. */
int _DkObjectsWaitAny(int count, PAL_HANDLE* handleArray, int64_t timeout_us,
                      PAL_HANDLE* polled) {
    int ret;

    if (count <= 0)
        return 0;

    if (count == 1 && handleArray[0]) {
        /* Special case of DkObjectsWaitAny(1, mutex/event, ...): perform a mutex-specific or
         * event-specific wait() callback instead of host-OS poll. */
        if (IS_HANDLE_TYPE(handleArray[0], mutex) || IS_HANDLE_TYPE(handleArray[0], event)) {
            const struct handle_ops* ops = HANDLE_OPS(handleArray[0]);
            assert(ops && ops->wait);

            int rv = ops->wait(handleArray[0], timeout_us);
            if (!rv)
                *polled = handleArray[0];
            return rv;
        }
    }

    /* Normal case of not mutex/event: poll on all handles in the array (their handle types can be
     * process, socket, pipe, device, file, eventfd). Note that this function is used only for
     * Graphene-internal purposes, so we can allocate arrays on stack (since they are small). */
    struct pollfd fds[count];
    PAL_HANDLE hdls[count];

    /* collect all FDs of all PAL handles that may report read/write events */
    int nfds = 0;
    for (int i = 0; i < count; i++) {
        PAL_HANDLE hdl = handleArray[i];
        if (!hdl)
            continue;

        /* ignore duplicate handles */
        for (int j = 0; j < i; j++)
            if (hdl == handleArray[j])
                continue;

        /* collect all internal-handle FDs (only those which are readable/writable) */
        for (int j = 0; j < MAX_FDS; j++) {
            PAL_FLG flags = HANDLE_HDR(hdl)->flags;

            if (hdl->generic.fds[j] == PAL_IDX_POISON)
                continue;
            if (flags & ERROR(j))
                continue;

            /* always ask host to wait for read event (if FD allows read events); however, no need
             * to ask host to wait for write event if FD is already known to be writable */
            int events = 0;
            events |= (flags & RFD(j)) ? POLLIN : 0;
            events |= ((flags & WFD(j)) && !(flags & WRITABLE(j))) ? POLLOUT : 0;

            if (events) {
                fds[nfds].fd      = hdl->generic.fds[j];
                fds[nfds].events  = events;
                fds[nfds].revents = 0;
                hdls[nfds]        = hdl;
                nfds++;
            }
        }
    }

    if (!nfds) {
        /* did not find any wait-able FDs (probably because their events were already cached) */
        ret = -PAL_ERROR_TRYAGAIN;
        goto out;
    }

    struct timespec timeout_ts;

    if (timeout_us >= 0) {
        int64_t sec = timeout_us / 1000000;
        int64_t microsec = timeout_us - (sec * 1000000);
        timeout_ts.tv_sec = sec;
        timeout_ts.tv_nsec = microsec * 1000;
    }

    ret = INLINE_SYSCALL(ppoll, 5, fds, nfds, timeout_us >= 0 ? &timeout_ts : NULL, NULL, 0);

    if (IS_ERR(ret)) {
        switch (ERRNO(ret)) {
            case EINTR:
            case ERESTART:
                ret = -PAL_ERROR_INTERRUPTED;
                break;
            default:
                ret = unix_to_pal_error(ERRNO(ret));
                break;
        }
        goto out;
    }

    if (!ret) {
        /* timed out */
        ret = -PAL_ERROR_TRYAGAIN;
        goto out;
    }

    PAL_HANDLE polled_hdl = NULL;

    for (int i = 0; i < nfds; i++) {
        if (!fds[i].revents)
            continue;

        /* One PAL handle can have MAX_FDS internal FDs, so we must select one handle (randomly)
         * from the ones on which the host reported events and then collect all revents on this
         * handle's internal FDs. Note that this is very inefficient. Each DkObjectsWaitAny()
         * returns only one of possibly  many event-ready PAL handles. */
        if (!polled_hdl)
            polled_hdl = hdls[i];

        if (polled_hdl != hdls[i])
            continue;

        for (int j = 0; j < MAX_FDS; j++) {
            if (!(HANDLE_HDR(polled_hdl)->flags & (RFD(j) | WFD(j))))
                continue;
            if (polled_hdl->generic.fds[j] != (PAL_IDX)fds[i].fd)
                continue;

            /* found internal FD of PAL handle that corresponds to the FD of event-ready fds[i] */
            if (fds[i].revents & POLLOUT)
                HANDLE_HDR(polled_hdl)->flags |= WRITABLE(j);
            if (fds[i].revents & (POLLHUP|POLLERR))
                HANDLE_HDR(polled_hdl)->flags |= ERROR(j);
        }
    }

    *polled = polled_hdl;
    ret = polled_hdl ? 0 : -PAL_ERROR_TRYAGAIN;
out:
    return ret;
}


/* Improved version of _DkObjectsWaitAny(): wait for specific events on all handles in the handle
 * array and return multiple events (including errors) reported by the host. Returns 0 on success,
 * PAL error on failure. */
int _DkObjectsWaitEvents(int count, PAL_HANDLE* handleArray, PAL_FLG* events, PAL_FLG* ret_events,
                         int64_t timeout_us) {
    int ret;

    if (count <= 0)
        return 0;

    if (count == 1 && handleArray[0]) {
        /* Special case of DkObjectsWaitEvents(1, mutex/event, ...): perform a mutex-specific or
         * event-specific wait() callback instead of host-OS poll. */
        if (IS_HANDLE_TYPE(handleArray[0], mutex) || IS_HANDLE_TYPE(handleArray[0], event)) {
            const struct handle_ops* ops = HANDLE_OPS(handleArray[0]);
            assert(ops && ops->wait);

            int rv = ops->wait(handleArray[0], timeout_us);
            if (!rv)
                ret_events[0] = PAL_WAIT_SIGNAL;
            return rv;
        }
    }

    /* Normal case of not mutex/event: poll on all handles in the array (their handle types can be
     * process, socket, pipe, device, file, eventfd). */
    struct pollfd* fds = malloc(count * sizeof(struct pollfd));
    if (!fds) {
        return -PAL_ERROR_NOMEM;
    }

    int* offsets = malloc(count * sizeof(int));
    if (!offsets) {
        free(fds);
        return -PAL_ERROR_NOMEM;
    }

    /* collect all FDs of all PAL handles that may report read/write events */
    int nfds = 0;
    for (int i = 0; i < count; i++) {
        ret_events[i] = 0;

        PAL_HANDLE hdl = handleArray[i];
        if (!hdl)
            continue;

        /* ignore duplicate handles */
        for (int j = 0; j < i; j++)
            if (hdl == handleArray[j])
                continue;

        /* collect all internal-handle FDs (only those which are readable/writable) */
        for (int j = 0; j < MAX_FDS; j++) {
            PAL_FLG flags = HANDLE_HDR(hdl)->flags;

            if (hdl->generic.fds[j] == PAL_IDX_POISON)
                continue;
            if (flags & ERROR(j))
                continue;

            /* always ask host to wait for read event (if FD allows read events); however, no need
             * to ask host to wait for write event if FD is already known to be writable */
            int fdevents = 0;
            fdevents |= ((flags & RFD(j)) && (events[i] & PAL_WAIT_READ)) ? POLLIN : 0;
            fdevents |= ((flags & WFD(j)) && (events[i] & PAL_WAIT_WRITE)) ? POLLOUT : 0;

            if (fdevents) {
                fds[nfds].fd      = hdl->generic.fds[j];
                fds[nfds].events  = fdevents;
                fds[nfds].revents = 0;
                offsets[nfds]     = i;
                nfds++;
            }
        }
    }

    if (!nfds) {
        /* did not find any wait-able FDs (LibOS supplied closed/errored FDs or empty events) */
        ret = -PAL_ERROR_TRYAGAIN;
        goto out;
    }

    struct timespec timeout_ts;

    if (timeout_us >= 0) {
        int64_t sec = timeout_us / 1000000;
        int64_t microsec = timeout_us - (sec * 1000000);
        timeout_ts.tv_sec = sec;
        timeout_ts.tv_nsec = microsec * 1000;
    }

    ret = INLINE_SYSCALL(ppoll, 5, fds, nfds, timeout_us >= 0 ? &timeout_ts : NULL, NULL, 0);

    if (IS_ERR(ret)) {
        switch (ERRNO(ret)) {
            case EINTR:
            case ERESTART:
                ret = -PAL_ERROR_INTERRUPTED;
                break;
            default:
                ret = unix_to_pal_error(ERRNO(ret));
                break;
        }
        goto out;
    }

    if (!ret) {
        /* timed out */
        ret = -PAL_ERROR_TRYAGAIN;
        goto out;
    }

    for (int i = 0; i < nfds; i++) {
        if (!fds[i].revents)
            continue;

        int j = offsets[i];
        if (fds[i].revents & POLLIN)
            ret_events[j] |= PAL_WAIT_READ;
        if (fds[i].revents & POLLOUT)
            ret_events[j] |= PAL_WAIT_WRITE;
        if (fds[i].revents & (POLLHUP|POLLERR|POLLNVAL))
            ret_events[j] |= PAL_WAIT_ERROR;
    }

    ret = 0;
out:
    free(fds);
    free(offsets);
    return ret;
}
