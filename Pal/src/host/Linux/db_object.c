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

#include <asm/errno.h>
#include <linux/poll.h>
#include <linux/time.h>
#include <linux/wait.h>

#include "api.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"

/* Wait on a synchronization handle and return 0 if this handle's event was triggered or error
 * code otherwise (e.g., due to timeout). */
int _DkSynchronizationObjectWait(PAL_HANDLE handle, int64_t timeout_us) {
    assert(IS_HANDLE_TYPE(handle, mutex) || IS_HANDLE_TYPE(handle, event));

    const struct handle_ops* ops = HANDLE_OPS(handle);
    if (!ops || !ops->wait)
        return -PAL_ERROR_NOTIMPLEMENTED;

    return ops->wait(handle, timeout_us);
}

/* Wait for specific events on all handles in the handle array and return multiple events
 * (including errors) reported by the host. Return 0 on success, PAL error on failure. */
int _DkStreamsWaitEvents(size_t count, PAL_HANDLE* handle_array, PAL_FLG* events, PAL_FLG* ret_events,
                         int64_t timeout_us) {
    int ret;

    if (count == 0)
        return 0;

    struct pollfd* fds = malloc(count * MAX_FDS * sizeof(*fds));
    if (!fds) {
        return -PAL_ERROR_NOMEM;
    }

    size_t* offsets = malloc(count * MAX_FDS * sizeof(*offsets));
    if (!offsets) {
        free(fds);
        return -PAL_ERROR_NOMEM;
    }

    /* collect all FDs of all PAL handles that may report read/write events */
    size_t nfds = 0;
    for (size_t i = 0; i < count; i++) {
        ret_events[i] = 0;

        PAL_HANDLE hdl = handle_array[i];
        if (!hdl)
            continue;

        /* collect all internal-handle FDs (only those which are readable/writable) */
        for (size_t j = 0; j < MAX_FDS; j++) {
            PAL_FLG flags = HANDLE_HDR(hdl)->flags;

            /* hdl might be a mutex/event/non-pollable object, simply ignore it */
            if (hdl->generic.fds[j] == PAL_IDX_POISON)
                continue;
            if (flags & ERROR(j))
                continue;

            int fdevents = 0;
            fdevents |= ((flags & RFD(j)) && (events[i] & PAL_WAIT_READ)) ? POLLIN : 0;
            fdevents |= ((flags & WFD(j)) && (events[i] & PAL_WAIT_WRITE)) ? POLLOUT : 0;

            if (fdevents) {
                fds[nfds].fd      = hdl->generic.fds[j];
                fds[nfds].events  = fdevents;
                fds[nfds].revents = 0;
                offsets[nfds] = i;
                nfds++;
            }
        }
    }

    if (!nfds) {
        /* did not find any waitable FDs (LibOS supplied closed/errored FDs or empty events) */
        ret = -PAL_ERROR_TRYAGAIN;
        goto out;
    }

    struct timespec timeout_ts;

    if (timeout_us >= 0) {
        int64_t sec        = timeout_us / 1000000;
        int64_t microsec   = timeout_us - sec * 1000000;
        timeout_ts.tv_sec  = sec;
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

    for (size_t i = 0; i < nfds; i++) {
        if (!fds[i].revents)
            continue;

        size_t j = offsets[i];

        /* update revents */
        if (fds[i].revents & POLLIN)
            ret_events[j] |= PAL_WAIT_READ;
        if (fds[i].revents & POLLOUT)
            ret_events[j] |= PAL_WAIT_WRITE;
        if (fds[i].revents & (POLLHUP | POLLERR | POLLNVAL))
            ret_events[j] |= PAL_WAIT_ERROR;

        /* update handle's internal fields (flags) */
        PAL_HANDLE hdl = handle_array[j];
        assert(hdl);
        for (size_t k = 0; k < MAX_FDS; k++) {
            if (hdl->generic.fds[k] != (PAL_IDX)fds[i].fd)
                continue;
            if (fds[i].revents & (POLLHUP|POLLERR|POLLNVAL))
                HANDLE_HDR(hdl)->flags |= ERROR(k);
        }
    }

    ret = 0;
out:
    free(fds);
    free(offsets);
    return ret;
}
