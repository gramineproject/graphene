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
 * This file contains operands to handle streams with URIs that have
 * "eventfd:".
 */

#include "pal_defs.h"
#include "pal_linux_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_error.h"
#include "pal_error.h"
#include "pal_security.h"
#include "pal_debug.h"
#include "api.h"

#include <linux/types.h>
typedef __kernel_pid_t pid_t;
#include <asm/fcntl.h>
#include <asm/poll.h>
#include <linux/un.h>
#include <sys/eventfd.h>

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

static int eventfd_pal_open(PAL_HANDLE *handle, const char * type, const char * uri, int access,
        int share, int create, int options) {
    int ret;

    if ((strcmp_static(type, "eventfd") != 0) || (*uri != '\0')) {
        return -PAL_ERROR_INVAL;
    }

    //Note: called thro DkStreamOpen..so using create parameter
    //to set initval. One issue..is eventfd's initval is supposed to be uint32,
    //while create is int32 type.
    ret = ocall_eventfd(create, eventfd_type(options));

    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    PAL_HANDLE hdl = malloc(HANDLE_SIZE(eventfd));
    SET_HANDLE_TYPE(hdl, eventfd);

    //Note: Only 1 eventfd FD per pal-handle, using index 0 in macros below.
    HANDLE_HDR(hdl)->flags |= RFD(0) | WFD(0) | WRITABLE(0);

    hdl->eventfd.fd = ret;
    hdl->eventfd.nonblocking = (options & PAL_OPTION_NONBLOCK) ?
            PAL_TRUE :
            PAL_FALSE;
    *handle = hdl;

    return 0;

}

/* 'read' operation of eventfd stream. offset does not apply here. */
static int64_t eventfd_pal_read(PAL_HANDLE handle, uint64_t offset, uint64_t len, void * buffer) {
    if (offset)
        return -PAL_ERROR_INVAL;

    if (!IS_HANDLE_TYPE(handle, eventfd))
        return -PAL_ERROR_NOTCONNECTION;

    if (len != sizeof(uint64_t))
        return -PAL_ERROR_INVAL;

    int fd = handle->eventfd.fd;

    int bytes = ocall_read(fd, buffer, len);

    if (IS_ERR(bytes))
        return unix_to_pal_error(ERRNO(bytes));

    //Note: In non-blocking case, we can return with 0,
    //and according to man-page..application will get -EAGAIN..
    if (!bytes)
        return -PAL_ERROR_ENDOFSTREAM;

    return bytes;
}

/* 'write' operation of eventfd stream. offset does not apply here. */
static int64_t eventfd_pal_write(PAL_HANDLE handle, uint64_t offset, uint64_t len,
        const void * buffer) {
    if (offset)
        return -PAL_ERROR_INVAL;

    if (!IS_HANDLE_TYPE(handle, eventfd))
        return -PAL_ERROR_NOTCONNECTION;

    if (len != sizeof(uint64_t))
        return -PAL_ERROR_INVAL;

    int fd = handle->eventfd.fd;

    int bytes = ocall_write(fd, buffer, len);

    PAL_FLG writable = WRITABLE(0);

    if (IS_ERR(bytes)) {
        bytes = unix_to_pal_error(ERRNO(bytes));
        if (bytes == -PAL_ERROR_TRYAGAIN)
            HANDLE_HDR(handle)->flags &= ~writable;
        return bytes;
    }

    if ((uint64_t) bytes == len)
        HANDLE_HDR(handle)->flags |= writable;
    else
        HANDLE_HDR(handle)->flags &= ~writable;

    return bytes;
}

/* gets used for polling(query) on eventfd from LibOS. */
static int eventfd_pal_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR * attr) {
    if (handle->generic.fds[0] == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    attr->handle_type = PAL_GET_TYPE(handle);

    int efd = handle->eventfd.fd;
    int flags = HANDLE_HDR(handle)->flags;

    struct pollfd pfd = { .fd = efd, .events = POLLIN, .revents = 0 };
    int ret = ocall_poll(&pfd, 1, 0);

    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    attr->readable = (ret == 1 && pfd.revents == POLLIN);

    //TODO: Not sure, whether attr->disconnected is needed.
    attr->disconnected = flags & ERROR(0);
    attr->nonblocking = handle->eventfd.nonblocking;

    /* Note: In order to support usage, where application
     * can send real eventfd, to kernel module.
     * Application can send ioctl to fetch eventfd.fd, from LibOS.
     * This allows PAL to return the eventfd, to LibOS.
     */
    attr->no_of_fds = 1;
    attr->fds[0] = efd;

    return 0;
}

/* 'close' operation of eventfd stream. */
static int eventfd_pal_close(PAL_HANDLE handle) {
    if (IS_HANDLE_TYPE(handle, eventfd)) {
        if (handle->eventfd.fd != PAL_IDX_POISON) {
            ocall_close(handle->eventfd.fd);
            handle->eventfd.fd = PAL_IDX_POISON;
        }
        return 0;
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
