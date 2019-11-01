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
 * This file contains APIs for waiting on PAL handles (polling): DkObjectsWaitAny.
 */

#include "api.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_freebsd.h"
#include "pal_freebsd_defs.h"
#include "pal_internal.h"

#include <errno.h>
#include <sys/poll.h>
#include <sys/wait.h>
#include <time.h>

/* Wait for an event on any handle in the handle array and return this handle in polled.
 * If no ready-event handle was found, polled is set to NULL. */
int _DkObjectsWaitAny(int count, PAL_HANDLE* handleArray, int64_t timeout_us,
                      PAL_HANDLE* polled) {
    if (count <= 0)
        return 0;

    if (count == 1 && handleArray[0]) {
        /* Special case of DkObjectsWaitAny(1, mutex/event, ...): perform a mutex-specific or
         * event-specific wait() callback instead of host-OS poll. */
        if (IS_HANDLE_TYPE(handleArray[0], mutex) || IS_HANDLE_TYPE(handleArray[0], event)) {
            const struct handle_ops* ops = HANDLE_OPS(handleArray[0]);
            assert(ops && ops->wait);

            int rv = ops->wait(handleArray[0], timeout_us);
            if (rv == 0)
                *polled = handleArray[0];
            return rv;
        }
    }

    /* Normal case of not mutex/event: poll on all handles in the array (their handle types can be
     * process, socket, pipe, device, file, eventfd). */
    struct pollfd fds[count]; /* TODO: if count is too big, stack overflow may occur */
    PAL_HANDLE hdls[count];   /* TODO: if count is too big, stack overflow may occur */
    int nfds = 0;

    /* collect all FDs of all PAL handles that may report read/write events */
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
                fds[nfds].events  = events | POLLHUP | POLLERR;
                fds[nfds].revents = 0;
                hdls[nfds]        = hdl;
                nfds++;
            }
        }
    }

    if (!nfds) {
        /* did not find any wait-able FDs (probably because their events were already cached) */
        return -PAL_ERROR_TRYAGAIN;
    }

    ret = INLINE_SYSCALL(poll, 3, fds, nfds, timeout_us ? timeout_us : -1);

    if (IS_ERR(ret))
        switch (ERRNO(ret)) {
            case EINTR:
            case ERESTART:
                return -PAL_ERROR_INTERRUPTED;
            default:
                return unix_to_pal_error(ERRNO(ret));
        }

    if (!ret) {
        /* timed out */
        return -PAL_ERROR_TRYAGAIN;
    }

    PAL_HANDLE polled_hdl = NULL;

    for (int i = 0; i < nfds; i++) {
        if (!fds[i].revents)
            continue;

        /* One PAL handle can have MAX_FDS internal FDs, so we must select one handle (randomly)
         * from the ones on which the host reported events and then collect all revents on this
         * handle's internal FDs.
         * TODO: This is very inefficient. Each DkObjectsWaitAny() returns only one of possibly
         *       many event-ready PAL handles. We must introduce new DkObjectsWaitEvents(). */
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
            /* TODO: Why is there no READABLE flag? Are FDs always assumed to be readable? */
        }
    }

    *polled = polled_hdl;
    return polled_hdl ? 0 : -PAL_ERROR_TRYAGAIN;
}
