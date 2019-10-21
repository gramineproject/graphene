/* Copyright (C) 2019 Intel Corporation
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
 * db_eventfd.c
 *
 * This file contains operations to handle streams with URIs that have
 * "eventfd:".
 */

#include <asm/fcntl.h>
#include <asm/poll.h>
#include <linux/un.h>
#include <linux/time.h>
#include <linux/types.h>
#include <sys/eventfd.h>

#include "api.h"
#include "pal_defs.h"
#include "pal_linux_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_error.h"
#include "pal_error.h"
#include "pal_security.h"
#include "pal_debug.h"

static inline int eventfd_type(int options) {
    int type = 0;
    if (options & PAL_OPTION_NONBLOCK)
        type |= EFD_NONBLOCK;

    if (options & PAL_OPTION_CLOEXEC)
        type |= EFD_CLOEXEC;

    if (options & PAL_OPTION_EFD_SEMAPHORE)
        type |= EFD_SEMAPHORE;

    return type;
}
/* access & share do not get set. In eventfd(initval, flags), create set to initval,
 * flags set to options */
static int eventfd_pal_open(PAL_HANDLE* handle, const char* type, const char* uri, int access,
        int share, int create, int options) {
    int ret;

    __UNUSED(access);
    __UNUSED(share);

    if ((strcmp_static(type, "eventfd") != 0) || (*uri != '\0')) {
        return -PAL_ERROR_INVAL;
    }

    /* Using create arg as a work-around (note: initval is uint32 but create is int32).*/
    ret = INLINE_SYSCALL(eventfd2, 2, create, eventfd_type(options));

    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    PAL_HANDLE hdl = malloc(HANDLE_SIZE(eventfd));
    SET_HANDLE_TYPE(hdl, eventfd);

    //Note: using index 0, given that there is only 1 eventfd FD per pal-handle.
    HANDLE_HDR(hdl)->flags = RFD(0) | WFD(0) | WRITABLE(0);

    hdl->eventfd.fd = ret;
    hdl->eventfd.nonblocking = (options & PAL_OPTION_NONBLOCK) ? PAL_TRUE : PAL_FALSE;
    *handle = hdl;

    return 0;

}

/* offset does not apply here. */
static int64_t eventfd_pal_read(PAL_HANDLE handle, uint64_t offset, uint64_t len, void* buffer) {
    if (offset)
        return -PAL_ERROR_INVAL;

    if (!IS_HANDLE_TYPE(handle, eventfd))
        return -PAL_ERROR_NOTCONNECTION;

    if (len < sizeof(uint64_t))
        return -PAL_ERROR_INVAL;

    /* TODO: verify that the value returned in buffer is somehow meaningful
     * (to prevent Iago attacks) */
    int bytes = INLINE_SYSCALL(read, 3, handle->eventfd.fd, buffer, len);

    if (IS_ERR(bytes))
        return unix_to_pal_error(ERRNO(bytes));

    if (!bytes)
        return -PAL_ERROR_ENDOFSTREAM;

    return bytes;
}

/* offset does not apply here. */
static int64_t eventfd_pal_write(PAL_HANDLE handle, uint64_t offset, uint64_t len,
        const void* buffer) {
    if (offset)
        return -PAL_ERROR_INVAL;

    if (!IS_HANDLE_TYPE(handle, eventfd))
        return -PAL_ERROR_NOTCONNECTION;

    if (len < sizeof(uint64_t))
        return -PAL_ERROR_INVAL;

    int bytes = INLINE_SYSCALL(write, 3, handle->eventfd.fd, buffer, len);
    PAL_FLG writable = WRITABLE(0);

    if (IS_ERR(bytes)) {
        bytes = unix_to_pal_error(ERRNO(bytes));
        if (bytes == -PAL_ERROR_TRYAGAIN)
            HANDLE_HDR(handle)->flags &= ~writable;
        return bytes;
    }

    /* whether fd is writable or not, gets updated here,
     * to optimize polling logic in _DkObjectsWaitAny */
    if ((uint64_t) bytes == sizeof(uint64_t))
        HANDLE_HDR(handle)->flags |= writable;
    else
        HANDLE_HDR(handle)->flags &= ~writable;

    return bytes;
}

/* gets used for polling(query) on eventfd from LibOS. */
static int eventfd_pal_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    if (handle->generic.fds[0] == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    attr->handle_type = PAL_GET_TYPE(handle);
    int efd = handle->eventfd.fd;
    int flags = HANDLE_HDR(handle)->flags;

    struct pollfd pfd = { .fd = efd, .events = POLLIN, .revents = 0 };
    struct timespec tp = {0, 0};
    int ret = INLINE_SYSCALL(ppoll, 5, &pfd, 1, &tp, NULL, 0);

    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    attr->readable = (ret == 1 && pfd.revents == POLLIN);
    attr->disconnected = flags & ERROR(0);
    attr->nonblocking = handle->eventfd.nonblocking;

    /* For future use, so that Linux host kernel can send notifications to user-space apps.
     * App receives virtual FD from LibOS, but the Linux-host eventfd is memorized
     * here, such that this Linux-host eventfd can be retreived(by LibOS) during app's ioctl(). */
    attr->no_of_fds = 1;
    attr->fds[0] = efd;

    return 0;
}

static int eventfd_pal_close(PAL_HANDLE handle) {
    if (IS_HANDLE_TYPE(handle, eventfd)) {
        if (handle->eventfd.fd != PAL_IDX_POISON) {
            INLINE_SYSCALL(close, 1, handle->eventfd.fd);
            handle->eventfd.fd = PAL_IDX_POISON;
        }
    }

    return 0;
}

struct handle_ops eventfd_ops = {
    .open               = &eventfd_pal_open,
    .read               = &eventfd_pal_read,
    .write              = &eventfd_pal_write,
    .close              = &eventfd_pal_close,
    .attrquerybyhdl     = &eventfd_pal_attrquerybyhdl,
};
