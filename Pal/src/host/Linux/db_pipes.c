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
 * db_pipes.c
 *
 * This file contains oeprands to handle streams with URIs that start with
 * "pipe:" or "pipe.srv:".
 */

#include <linux/types.h>

#include "api.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_security.h"
typedef __kernel_pid_t pid_t;
#include <asm/errno.h>
#include <asm/fcntl.h>
#include <asm/poll.h>
#include <linux/time.h>
#include <linux/un.h>
#include <sys/socket.h>

#ifndef FIONREAD
#define FIONREAD 0x541B
#endif

static int pipe_path(int pipeid, char* path, int len) {
    /* use abstract UNIX sockets for pipes */
    memset(path, 0, len);

    if (pal_sec.pipe_prefix_id)
        return snprintf(path + 1, len - 1, GRAPHENE_UNIX_PREFIX_FMT "/%08x", pal_sec.pipe_prefix_id,
                        pipeid);
    else
        return snprintf(path + 1, len - 1, "/graphene/%08x", pipeid);
}

static int pipe_addr(int pipeid, struct sockaddr_un* addr) {
    addr->sun_family = AF_UNIX;
    return pipe_path(pipeid, (char*)addr->sun_path, sizeof(addr->sun_path));
}

static int pipe_listen(PAL_HANDLE* handle, PAL_NUM pipeid, int options) {
    int ret, fd;

    fd = INLINE_SYSCALL(socket, 3, AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | options, 0);
    if (IS_ERR(fd))
        return -PAL_ERROR_DENIED;

    struct sockaddr_un addr;

    if ((ret = pipe_addr(pipeid, &addr)) < 0)
        return ret;

    ret = INLINE_SYSCALL(bind, 3, fd, &addr, sizeof(addr.sun_path) - 1);

    if (IS_ERR(ret)) {
        INLINE_SYSCALL(close, 1, fd);

        switch (ERRNO(ret)) {
            case EINVAL:
                return -PAL_ERROR_INVAL;
            case EADDRINUSE:
                return -PAL_ERROR_STREAMEXIST;
            default:
                return -PAL_ERROR_DENIED;
        }
    }

    ret = INLINE_SYSCALL(listen, 2, fd, 1);
    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    PAL_HANDLE hdl = malloc(HANDLE_SIZE(pipe));
    SET_HANDLE_TYPE(hdl, pipesrv);
    HANDLE_HDR(hdl)->flags |= RFD(0);
    hdl->pipe.fd          = fd;
    hdl->pipe.pipeid      = pipeid;
    hdl->pipe.nonblocking = options & PAL_OPTION_NONBLOCK ? PAL_TRUE : PAL_FALSE;
    *handle               = hdl;
    return 0;
}

static int pipe_waitforclient(PAL_HANDLE handle, PAL_HANDLE* client) {
    if (!IS_HANDLE_TYPE(handle, pipesrv))
        return -PAL_ERROR_NOTSERVER;

    if (handle->pipe.fd == PAL_IDX_POISON)
        return -PAL_ERROR_DENIED;

    int newfd = INLINE_SYSCALL(accept4, 4, handle->pipe.fd, NULL, NULL, O_CLOEXEC);

    if (IS_ERR(newfd))
        switch (ERRNO(newfd)) {
            case EWOULDBLOCK:
                return -PAL_ERROR_TRYAGAIN;
            case ECONNABORTED:
                return -PAL_ERROR_CONNFAILED;
            default:
                return -PAL_ERROR_DENIED;
        }

    PAL_HANDLE clnt = malloc(HANDLE_SIZE(pipe));
    SET_HANDLE_TYPE(clnt, pipecli);
    HANDLE_HDR(clnt)->flags |= RFD(0) | WFD(0);
    clnt->pipe.fd          = newfd;
    clnt->pipe.pipeid      = handle->pipe.pipeid;
    clnt->pipe.nonblocking = PAL_FALSE;
    *client                = clnt;

    return 0;
}

static int pipe_connect(PAL_HANDLE* handle, PAL_NUM pipeid, int options) {
    int ret, fd;

    fd = INLINE_SYSCALL(socket, 3, AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | options, 0);

    if (IS_ERR(fd))
        return -PAL_ERROR_DENIED;

    struct sockaddr_un addr;

    if ((ret = pipe_addr(pipeid, &addr)) < 0)
        return ret;

    ret = INLINE_SYSCALL(connect, 3, fd, &addr, sizeof(addr.sun_path) - 1);

    if (IS_ERR(ret)) {
        INLINE_SYSCALL(close, 1, fd);
        switch (ERRNO(ret)) {
            case ECONNREFUSED:
                return -PAL_ERROR_STREAMNOTEXIST;
            case EINTR:
                return -PAL_ERROR_TRYAGAIN;
            default:
                return -PAL_ERROR_DENIED;
        }
    }

    PAL_HANDLE hdl = malloc(HANDLE_SIZE(pipe));
    SET_HANDLE_TYPE(hdl, pipe);
    HANDLE_HDR(hdl)->flags |= RFD(0) | WFD(0);
    hdl->pipe.fd          = fd;
    hdl->pipe.pipeid      = pipeid;
    hdl->pipe.nonblocking = (options & PAL_OPTION_NONBLOCK) ? PAL_TRUE : PAL_FALSE;
    *handle = hdl;

    return 0;
}

static int pipe_private(PAL_HANDLE* handle, int options) {
    int ret, fds[2];

    ret = INLINE_SYSCALL(socketpair, 4, AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | options, 0, fds);
    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    PAL_HANDLE hdl = malloc(HANDLE_SIZE(pipeprv));
    SET_HANDLE_TYPE(hdl, pipeprv);
    HANDLE_HDR(hdl)->flags |= RFD(0) | WFD(1);
    hdl->pipeprv.fds[0]      = fds[0];
    hdl->pipeprv.fds[1]      = fds[1];
    hdl->pipeprv.nonblocking = (options & PAL_OPTION_NONBLOCK) ? PAL_TRUE : PAL_FALSE;
    *handle                  = hdl;
    return 0;
}

/* 'open' operation of pipe stream. For each pipe stream, it is
   identified by a decimal number in URI. There could be two
   types: pipe and pipe.srv. They behave pretty much the same,
   except they are two ends of the pipe. */
static int pipe_open(PAL_HANDLE* handle, const char* type, const char* uri, int access, int share,
                     int create, int options) {
    if (!WITHIN_MASK(access, PAL_ACCESS_MASK) || !WITHIN_MASK(share, PAL_SHARE_MASK) ||
        !WITHIN_MASK(create, PAL_CREATE_MASK) || !WITHIN_MASK(options, PAL_OPTION_MASK))
        return -PAL_ERROR_INVAL;

    if (!strcmp_static(type, URI_TYPE_PIPE) && !*uri)
        return pipe_private(handle, options);

    char* endptr;
    PAL_NUM pipeid = strtol(uri, &endptr, 10);

    if (*endptr)
        return -PAL_ERROR_INVAL;

    if (!strcmp_static(type, URI_TYPE_PIPE_SRV))
        return pipe_listen(handle, pipeid, options);

    if (!strcmp_static(type, URI_TYPE_PIPE))
        return pipe_connect(handle, pipeid, options);

    return -PAL_ERROR_INVAL;
}

/* 'read' operation of pipe stream. offset does not apply here. */
static int64_t pipe_read(PAL_HANDLE handle, uint64_t offset, uint64_t len, void* buffer) {
    if (offset)
        return -PAL_ERROR_INVAL;

    if (!IS_HANDLE_TYPE(handle, pipecli) && !IS_HANDLE_TYPE(handle, pipeprv) &&
        !IS_HANDLE_TYPE(handle, pipe))
        return -PAL_ERROR_NOTCONNECTION;

    int fd        = IS_HANDLE_TYPE(handle, pipeprv) ? handle->pipeprv.fds[0] : handle->pipe.fd;
    int64_t bytes = 0;

    bytes = INLINE_SYSCALL(read, 3, fd, buffer, len);

    if (IS_ERR(bytes))
        bytes = unix_to_pal_error(ERRNO(bytes));

    if (!bytes)
        return -PAL_ERROR_ENDOFSTREAM;

    return bytes;
}

/* 'write' operation of pipe stream. offset does not apply here. */
static int64_t pipe_write(PAL_HANDLE handle, uint64_t offset, size_t len, const void* buffer) {
    if (offset)
        return -PAL_ERROR_INVAL;

    if (!IS_HANDLE_TYPE(handle, pipecli) && !IS_HANDLE_TYPE(handle, pipeprv) &&
        !IS_HANDLE_TYPE(handle, pipe))
        return -PAL_ERROR_NOTCONNECTION;

    int fd        = IS_HANDLE_TYPE(handle, pipeprv) ? handle->pipeprv.fds[1] : handle->pipe.fd;
    int64_t bytes = 0;

    bytes = INLINE_SYSCALL(write, 3, fd, buffer, len);
    if (IS_ERR(bytes))
        bytes = unix_to_pal_error(ERRNO(bytes));

    return bytes;
}

/* 'close' operation of pipe stream. */
static int pipe_close(PAL_HANDLE handle) {
    if (IS_HANDLE_TYPE(handle, pipeprv)) {
        if (handle->pipeprv.fds[0] != PAL_IDX_POISON) {
            INLINE_SYSCALL(close, 1, handle->pipeprv.fds[0]);
            handle->pipeprv.fds[0] = PAL_IDX_POISON;
        }
        if (handle->pipeprv.fds[1] != PAL_IDX_POISON) {
            INLINE_SYSCALL(close, 1, handle->pipeprv.fds[1]);
            handle->pipeprv.fds[1] = PAL_IDX_POISON;
        }
        return 0;
    }

    if (handle->pipe.fd != PAL_IDX_POISON) {
        INLINE_SYSCALL(close, 1, handle->pipe.fd);
        handle->pipe.fd = PAL_IDX_POISON;
    }

    return 0;
}

/* 'delete' operation of pipe stream. */
static int pipe_delete(PAL_HANDLE handle, int access) {
    if (IS_HANDLE_TYPE(handle, pipeprv)) {
        switch (access) {
            case 0:
                if (handle->pipeprv.fds[0] != PAL_IDX_POISON) {
                    INLINE_SYSCALL(close, 1, handle->pipeprv.fds[0]);
                    handle->pipeprv.fds[0] = PAL_IDX_POISON;
                }
                if (handle->pipeprv.fds[1] != PAL_IDX_POISON) {
                    INLINE_SYSCALL(close, 1, handle->pipeprv.fds[1]);
                    handle->pipeprv.fds[1] = PAL_IDX_POISON;
                }
                break;
            case PAL_DELETE_RD:
                if (handle->pipeprv.fds[0] != PAL_IDX_POISON) {
                    INLINE_SYSCALL(close, 1, handle->pipeprv.fds[0]);
                    handle->pipeprv.fds[0] = PAL_IDX_POISON;
                }
                break;
            case PAL_DELETE_WR:
                if (handle->pipeprv.fds[1] != PAL_IDX_POISON) {
                    INLINE_SYSCALL(close, 1, handle->pipeprv.fds[1]);
                    handle->pipeprv.fds[1] = PAL_IDX_POISON;
                }
                break;
            default:
                return -PAL_ERROR_INVAL;
        }
    }

    if (handle->pipe.fd == PAL_IDX_POISON)
        return 0;

    int shutdown;
    switch (access) {
        case 0:
            shutdown = SHUT_RDWR;
            break;
        case PAL_DELETE_RD:
            shutdown = SHUT_RD;
            break;
        case PAL_DELETE_WR:
            shutdown = SHUT_WR;
            break;
        default:
            return -PAL_ERROR_INVAL;
    }

    INLINE_SYSCALL(shutdown, 2, handle->pipe.fd, shutdown);

    return 0;
}

static int pipe_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    int ret;
    int val;

    if (handle->pipe.fd == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    attr->handle_type  = HANDLE_HDR(handle)->type;
    attr->nonblocking  = IS_HANDLE_TYPE(handle, pipeprv) ? handle->pipeprv.nonblocking
                                                         : handle->pipe.nonblocking;
    attr->disconnected = HANDLE_HDR(handle)->flags & ERROR(0);

    /* get number of bytes available for reading (doesn't make sense for "listening" pipes) */
    attr->pending_size = 0;
    if (!IS_HANDLE_TYPE(handle, pipesrv)) {
        ret = INLINE_SYSCALL(ioctl, 3, handle->pipe.fd, FIONREAD, &val);
        if (IS_ERR(ret))
            return unix_to_pal_error(ERRNO(ret));

        attr->pending_size = val;
    }

    /* query if there is data available for reading/writing */
    if (IS_HANDLE_TYPE(handle, pipeprv)) {
        /* for private pipe, readable and writable are queried on different fds */
        struct pollfd pfd[2] = {{.fd = handle->pipeprv.fds[0], .events = POLLIN,  .revents = 0},
                                {.fd = handle->pipeprv.fds[1], .events = POLLOUT, .revents = 0}};
        struct timespec tp   = {0, 0};
        ret = INLINE_SYSCALL(ppoll, 5, &pfd, 2, &tp, NULL, 0);
        if (IS_ERR(ret))
            return unix_to_pal_error(ERRNO(ret));

        attr->readable = (ret >= 1 && pfd[0].revents & POLLIN);
        attr->writable = (ret >= 1 && pfd[1].revents & POLLOUT);
    } else {
        /* for non-private pipes, both readable and writable are queried on the same fd */
        short pfd_events = POLLIN;
        if (!IS_HANDLE_TYPE(handle, pipesrv)) {
            /* querying for writing doesn't make sense for "listening" pipes */
            pfd_events |= POLLOUT;
        }

        struct pollfd pfd  = {.fd = handle->pipe.fd, .events = pfd_events, .revents = 0};
        struct timespec tp = {0, 0};
        ret = INLINE_SYSCALL(ppoll, 5, &pfd, 1, &tp, NULL, 0);
        if (IS_ERR(ret))
            return unix_to_pal_error(ERRNO(ret));

        attr->readable = (ret == 1 && pfd.revents & POLLIN);
        attr->writable = (ret == 1 && pfd.revents & POLLOUT);
    }

    return 0;
}

static int pipe_attrsetbyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    if (handle->generic.fds[0] == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    int ret;
    PAL_BOL* nonblocking = (HANDLE_HDR(handle)->type == pal_type_pipeprv)
                               ? &handle->pipeprv.nonblocking
                               : &handle->pipe.nonblocking;

    if (attr->nonblocking != *nonblocking) {
        ret = INLINE_SYSCALL(fcntl, 3, handle->generic.fds[0], F_SETFL,
                             attr->nonblocking ? O_NONBLOCK : 0);

        if (IS_ERR(ret))
            return unix_to_pal_error(ERRNO(ret));

        *nonblocking = attr->nonblocking;
    }

    return 0;
}

static int pipe_getname(PAL_HANDLE handle, char* buffer, size_t count) {
    size_t old_count = count;
    int ret;

    const char* prefix = NULL;
    size_t prefix_len  = 0;

    switch (PAL_GET_TYPE(handle)) {
        case pal_type_pipesrv:
        case pal_type_pipecli:
            prefix_len = static_strlen(URI_TYPE_PIPE_SRV);
            prefix     = URI_TYPE_PIPE_SRV;
            break;
        case pal_type_pipe:
            prefix_len = static_strlen(URI_TYPE_PIPE);
            prefix     = URI_TYPE_PIPE;
            break;
        case pal_type_pipeprv:
        default:
            return -PAL_ERROR_INVAL;
    }

    if (prefix_len >= count)
        return -PAL_ERROR_OVERFLOW;

    memcpy(buffer, prefix, prefix_len);
    buffer[prefix_len] = ':';
    buffer += prefix_len + 1;
    count -= prefix_len + 1;

    ret = snprintf(buffer, count, "%lu\n", handle->pipe.pipeid);
    if (buffer[ret - 1] != '\n') {
        memset(buffer, 0, count);
        return -PAL_ERROR_OVERFLOW;
    }

    buffer[ret - 1] = 0;
    buffer += ret - 1;
    count -= ret - 1;

    return old_count - count;
}

struct handle_ops pipe_ops = {
    .getname        = &pipe_getname,
    .open           = &pipe_open,
    .waitforclient  = &pipe_waitforclient,
    .read           = &pipe_read,
    .write          = &pipe_write,
    .close          = &pipe_close,
    .delete         = &pipe_delete,
    .attrquerybyhdl = &pipe_attrquerybyhdl,
    .attrsetbyhdl   = &pipe_attrsetbyhdl,
};

struct handle_ops pipeprv_ops = {
    .open           = &pipe_open,
    .read           = &pipe_read,
    .write          = &pipe_write,
    .close          = &pipe_close,
    .attrquerybyhdl = &pipe_attrquerybyhdl,
    .attrsetbyhdl   = &pipe_attrsetbyhdl,
};
