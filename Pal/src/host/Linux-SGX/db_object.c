/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs for waiting on PAL handles (polling).
 */

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
#include "pal_linux_error.h"

/* Wait on a synchronization handle and return 0 if this handle's event was triggered or error
 * code otherwise (e.g., due to timeout). */
int _DkSynchronizationObjectWait(PAL_HANDLE handle, int64_t timeout_us) {
    assert(IS_HANDLE_TYPE(handle, mutex) || IS_HANDLE_TYPE(handle, event));

    const struct handle_ops* ops = HANDLE_OPS(handle);
    if (!ops || !ops->wait)
        return -PAL_ERROR_NOTIMPLEMENTED;

    return ops->wait(handle, timeout_us);
}

/* TODO: this should take into account `handle->pipe.handshake_done`. For more details see
 * "Pal/src/host/Linux-SGX/db_pipes.c". */
/* Wait for specific events on all handles in the handle array and return multiple events
 * (including errors) reported by the host. Return 0 on success, PAL error on failure. */
int _DkStreamsWaitEvents(size_t count, PAL_HANDLE* handle_array, PAL_FLG* events,
                         PAL_FLG* ret_events, int64_t timeout_us) {
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
    size_t ret_events_updated = 0;
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
            if (flags & ERROR(j)) {
                /* PAL handle is requested for read/write but already marked with error:
                 * skip it but update its ret_events */
                if (events[i] & (PAL_WAIT_READ | PAL_WAIT_WRITE)) {
                    ret_events[i] |= PAL_WAIT_ERROR;
                    ret_events_updated++;
                }
                continue;
            }

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
        if (ret_events_updated > 0) {
            /* we skip actual ppoll, but there was at least one PAL handle with updated ret_events
             */
            ret = 0;
        } else {
            /* did not find any waitable FDs (LibOS supplied closed/errored FDs or empty events) */
            ret = -PAL_ERROR_TRYAGAIN;
        }
        goto out;
    }

    ret = ocall_poll(fds, nfds, timeout_us);

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
            if (fds[i].revents & (POLLHUP | POLLERR | POLLNVAL))
                HANDLE_HDR(hdl)->flags |= ERROR(k);
        }
    }

    ret = 0;
out:
    free(fds);
    free(offsets);
    return ret;
}
