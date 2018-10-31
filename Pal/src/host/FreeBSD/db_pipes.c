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
 * db_pipes.c
 *
 * This file contains oeprands to handle streams with URIs that start with
 * "pipe:" or "pipe.srv:".
 */

#include "pal_defs.h"
#include "pal_freebsd_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_freebsd.h"
#include "pal_error.h"
#include "pal_security.h"
#include "pal_debug.h"
#include "api.h"

#include <sys/types.h>
typedef __kernel_pid_t pid_t;
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <sys/filio.h>

#if USE_PIPE_SYSCALL == 1
# include <sys/msg.h>
#endif

static int pipe_path (int pipeid, char * path, int len)
{
    /* use abstract UNIX sockets for pipes */
    memset(path, 0, len);
    if (pal_sec.pipe_prefix)
        return snprintf(path, len, GRAPHENE_PIPEDIR "/%08x/%s%08x",
                        pal_sec.domain_id,
                        pal_sec.pipe_prefix, pipeid);
    else
        return snprintf(path, len, GRAPHENE_PIPEDIR "/%08x/%08x",
                        pal_sec.domain_id, pipeid);
}

static int pipe_addr (int pipeid, struct sockaddr_un * addr)
{
    addr->sun_family = AF_UNIX;
    return pipe_path(pipeid, (char *) addr->sun_path, sizeof(addr->sun_path));
}

static int pipe_listen (PAL_HANDLE * handle, PAL_NUM pipeid, int options)
{
    int ret, fd;
    options = HOST_SOCKET_OPTIONS(options);

    fd = INLINE_SYSCALL(socket, 3, AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|options,
                        0);
    if (IS_ERR(fd))
        return -PAL_ERROR_DENIED;

    struct sockaddr_un addr;

    if ((ret = pipe_addr(pipeid, &addr)) < 0)
        return ret;

    ret = INLINE_SYSCALL(bind, 3, fd, &addr, sizeof(addr.sun_path) - 1);

    if (IS_ERR(ret)) {
        INLINE_SYSCALL(close, 1, fd);

        switch(ERRNO(ret)) {
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
    hdl->hdr.flags |= RFD(0);
    hdl->pipe.fd = fd;
    hdl->pipe.pipeid = pipeid;
    hdl->pipe.nonblocking = options & O_NONBLOCK ?
                            PAL_TRUE : PAL_FALSE;
    *handle = hdl;
    return 0;
}

static int pipe_waitforclient (PAL_HANDLE handle, PAL_HANDLE * client)
{
    if (!IS_HANDLE_TYPE(handle, pipesrv))
        return -PAL_ERROR_NOTSERVER;

    if (handle->pipe.fd == PAL_IDX_POISON)
        return -PAL_ERROR_DENIED;

    int newfd = INLINE_SYSCALL(accept4, 4, handle->pipe.fd, NULL, NULL,
                               SOCK_CLOEXEC);
    if (IS_ERR(newfd))
        switch (ERRNO(newfd)) {
            case EWOULDBLOCK:
                return -PAL_ERROR_TRYAGAIN;
            case ECONNABORTED:
                return -PAL_ERROR_CONNFAILED;
            default:
                return -PAL_ERROR_DENIED;
        }

#if USE_PIPE_SYSCALL == 1
    int pipes[2];
    struct msghdr hdr;
    struct iovec iov;
    char cbuf[CMSG_LEN(2 * sizeof(int))];
    char b = 0;
    int ret = 0;

    memset(&hdr, 0, sizeof(struct msghdr));
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = cbuf;
    hdr.msg_controllen = sizeof(cbuf);
    iov.iov_base = &b;
    iov.iov_len = 1;

    ret = INLINE_SYSCALL(recvmsg, 3, newfd, &hdr, 0);

    INLINE_SYSCALL(close, 1, newfd);

    struct cmsghdr * chdr = CMSG_FIRSTHDR(&hdr);

    if (IS_ERR(ret) || chdr->cmsg_type != SCM_RIGHTS)
        return -PAL_ERROR_DENIED;

    memcpy(pipes, CMSG_DATA(chdr), sizeof(int) * 2);

    PAL_HANDLE clnt = malloc(HANDLE_SIZE(pipeprv));
    SET_HANDLE_TYPE(clnt, pipeprv);
    clnt->hdr.flags |= RFD(0)|WFD(1)|WRITEABLE(1);
    clnt->pipeprv.fds[0] = pipes[0];
    clnt->pipeprv.fds[1] = pipes[1];
    *client = clnt;
#else
    PAL_HANDLE clnt = malloc(HANDLE_SIZE(pipe));
    SET_HANDLE_TYPE(clnt, pipecli);
    clnt->hdr.flags |= RFD(0)|WFD(0)|WRITEABLE(0);
    clnt->pipe.fd = newfd;
    clnt->pipe.nonblocking = PAL_FALSE;
    clnt->pipe.pipeid = handle->pipe.pipeid;
    *client = clnt;
#endif

    return 0;
}

static int pipe_connect (PAL_HANDLE * handle, PAL_NUM pipeid, int options)
{
    int ret, fd;

#if USE_PIPE_SYSCALL == 1
    fd = INLINE_SYSCALL(socket, 3, AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
#else
    options = HOST_SOCKET_OPTIONS(options);

    fd = INLINE_SYSCALL(socket, 3, AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|options,
                        0);
#endif

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

#if USE_PIPE_SYSCALL == 1
    int pipes[4], tmp;

    options = HOST_SOCKET_OPTIONS(options);

    INLINE_SYSCALL(pipe2, 2, &pipes[0], O_CLOEXEC|options);
    INLINE_SYSCALL(pipe2, 2, &pipes[2], O_CLOEXEC|options);

    tmp = pipes[3];
    pipes[3] = pipes[1];
    pipes[1] = tmp;

    struct msghdr hdr;
    struct iovec iov;
    char cbuf[CMSG_LEN(2 * sizeof(int))];
    char b = 0;

    memset(&hdr, 0, sizeof(struct msghdr));
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = cbuf;
    hdr.msg_controllen = sizeof(cbuf);
    iov.iov_base = &b;
    iov.iov_len = 1;
    struct cmsghdr * chdr = CMSG_FIRSTHDR(&hdr);
    chdr->cmsg_level = SOL_SOCKET;
    chdr->cmsg_type = SCM_RIGHTS;
    chdr->cmsg_len = CMSG_LEN(sizeof(int) * 2);
    memcpy(CMSG_DATA(chdr), &pipes[2], sizeof(int) * 2);

    ret = INLINE_SYSCALL(sendmsg, 3, fd, &hdr, 0);
    INLINE_SYSCALL(close, 1, fd);
    INLINE_SYSCALL(close, 1, pipes[2]);
    INLINE_SYSCALL(close, 1, pipes[3]);

    if (IS_ERR(ret)) {
        INLINE_SYSCALL(close, 1, pipes[0]);
        INLINE_SYSCALL(close, 1, pipes[1]);
        return -PAL_ERROR_DENIED;
    }

    PAL_HANDLE hdl = malloc(HANDLE_SIZE(pipeprv));
    SET_HANDLE_TYPE(hdl, pipeprv);
    hdl->hdr.flags |= RFD(0)|WFD(1)|WRITEABLE(1);
    hdl->pipeprv.fds[0] = pipes[0];
    hdl->pipeprv.fds[1] = pipes[1];
    hdl->pipeprv.nonblocking = (options & O_NONBLOCK) ?
                               PAL_TRUE : PAL_FALSE;
#else
    PAL_HANDLE hdl = malloc(HANDLE_SIZE(pipe));
    SET_HANDLE_TYPE(hdl, pipe);
    hdl->hdr.flags |= RFD(0)|WFD(0)|WRITEABLE(0);
    hdl->pipe.fd = fd;
    hdl->pipe.pipeid = pipeid;
    hdl->pipe.nonblocking = (options & O_NONBLOCK) ?
                            PAL_TRUE : PAL_FALSE;
#endif
    *handle = hdl;

    return 0;
}

static int pipe_private (PAL_HANDLE * handle, int options)
{
    int ret, fds[2];

#if USE_PIPE_SYSCALL == 1
    options = HOST_OPTIONS(options);
    ret = INLINE_SYSCALL(pipe2, 2, fds, O_CLOEXEC|options);
#else
    options = HOST_SOCKET_OPTIONS(options);
    ret = INLINE_SYSCALL(socketpair, 4, AF_UNIX,
                         SOCK_STREAM|SOCK_CLOEXEC|options, 0, fds);
#endif
    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    PAL_HANDLE hdl = malloc(HANDLE_SIZE(pipeprv));
    SET_HANDLE_TYPE(hdl, pipeprv);
    hdl->hdr.flags |= RFD(0)|WFD(1)|WRITEABLE(1);
    hdl->pipeprv.fds[0] = fds[0];
    hdl->pipeprv.fds[1] = fds[1];
    hdl->pipeprv.nonblocking = (options & O_NONBLOCK) ?
                                PAL_TRUE : PAL_FALSE;
    *handle = hdl;
    return 0;
}

/* 'open' operation of pipe stream. For each pipe stream, it is
   identified by a decimal number in URI. There could be two
   types: pipe and pipe.srv. They behave pretty much the same,
   except they are two ends of the pipe. */
static int pipe_open (PAL_HANDLE *handle, const char * type, const char * uri,
                      int access, int share, int create, int options)
{
    if (strpartcmp_static(type, "pipe:") && !*uri)
        return pipe_private(handle, options);

    char * endptr;
    PAL_NUM pipeid = strtol(uri, &endptr, 10);

    if (*endptr)
        return -PAL_ERROR_INVAL;

    options = HOST_OPTIONS(options & PAL_OPTION_MASK);

    if (strpartcmp_static(type, "pipe.srv:"))
        return pipe_listen(handle, pipeid, options);

    if (strpartcmp_static(type, "pipe:"))
        return pipe_connect(handle, pipeid, options);

    return -PAL_ERROR_INVAL;
}

/* 'read' operation of pipe stream. offset does not apply here. */
static int pipe_read (PAL_HANDLE handle, int offset, int len,
                      void * buffer)
{
    if (!IS_HANDLE_TYPE(handle, pipecli) &&
        !IS_HANDLE_TYPE(handle, pipeprv) &&
        !IS_HANDLE_TYPE(handle, pipe))
        return -PAL_ERROR_NOTCONNECTION;

    int fd = IS_HANDLE_TYPE(handle, pipeprv) ? handle->pipeprv.fds[0] :
             handle->pipe.fd;
    int bytes = 0;

#if USE_PIPE_SYSCALL == 1
    if (IS_HANDLE_TYPE(handle, pipeprv)) {
        bytes = INLINE_SYSCALL(read, 3, fd, buffer, len);
    } else {
#endif
        struct msghdr hdr;
        struct iovec iov;

        iov.iov_base = buffer;
        iov.iov_len = len;
        hdr.msg_name = NULL;
        hdr.msg_namelen = 0;
        hdr.msg_iov = &iov;
        hdr.msg_iovlen = 1;
        hdr.msg_control = NULL;
        hdr.msg_controllen = 0;
        hdr.msg_flags = 0;

        bytes = INLINE_SYSCALL(recvmsg, 3, fd, &hdr, 0);
#if USE_PIPE_SYSCALL == 1
    }
#endif

    if (IS_ERR(bytes))
        switch(ERRNO(bytes)) {
            case EWOULDBLOCK:
                return-PAL_ERROR_TRYAGAIN;
            case EINTR:
                return -PAL_ERROR_INTERRUPTED;
            default:
                return -PAL_ERROR_DENIED;
        }

    if (!bytes)
        return -PAL_ERROR_ENDOFSTREAM;

    return bytes;
}

/* 'write' operation of pipe stream. offset does not apply here. */
static int pipe_write (PAL_HANDLE handle, int offset, int len,
                       const void * buffer)
{
    if (!IS_HANDLE_TYPE(handle, pipecli) &&
        !IS_HANDLE_TYPE(handle, pipeprv) &&
        !IS_HANDLE_TYPE(handle, pipe))
        return -PAL_ERROR_NOTCONNECTION;

    int fd = IS_HANDLE_TYPE(handle, pipeprv) ? handle->pipeprv.fds[1] :
             handle->pipe.fd;
    int bytes = 0;

#if USE_PIPE_SYSCALL == 1
    if (IS_HANDLE_TYPE(handle, pipeprv)) {
        bytes = INLINE_SYSCALL(write, 3, fd, buffer, len);
    } else {
#endif
        struct msghdr hdr;
        struct iovec iov;

        iov.iov_base = (void *) buffer;
        iov.iov_len = len;
        hdr.msg_name = NULL;
        hdr.msg_namelen = 0;
        hdr.msg_iov = &iov;
        hdr.msg_iovlen = 1;
        hdr.msg_control = NULL;
        hdr.msg_controllen = 0;
        hdr.msg_flags = 0;

        bytes = INLINE_SYSCALL(sendmsg, 3, fd, &hdr, MSG_NOSIGNAL);
#if USE_PIPE_SYSCALL == 1
    }
#endif

    PAL_FLG writeable = IS_HANDLE_TYPE(handle, pipeprv) ? WRITEABLE(1) :
                        WRITEABLE(0);

    if (IS_ERR(bytes))
        switch(ERRNO(bytes)) {
            case EWOULDBLOCK:
                handle->hdr.flags &= ~writeable;
                return-PAL_ERROR_TRYAGAIN;
            case EINTR:
                return -PAL_ERROR_INTERRUPTED;
            default:
                return -PAL_ERROR_DENIED;
        }

    if (bytes == len)
        handle->hdr.flags |= writeable;
    else
        handle->hdr.flags &= ~writeable;

    return bytes;
}

/* 'close' operation of pipe stream. */
static int pipe_close (PAL_HANDLE handle)
{
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
static int pipe_delete (PAL_HANDLE handle, int access)
{
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

static int pipe_attrquerybyhdl (PAL_HANDLE handle, PAL_STREAM_ATTR * attr)
{
    int ret, val;

    if (handle->hdr.fds[0] == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    ret = INLINE_SYSCALL(ioctl, 3, handle->hdr.fds[0], FIONREAD, &val);
    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    attr->handle_type  = pal_type_pipe;
    attr->disconnected = handle->hdr.flags & ERROR(0);
    attr->nonblocking  = (handle->hdr.type == pal_type_pipeprv) ?
                         handle->pipeprv.nonblocking : handle->pipe.nonblocking;
    attr->readable     = val > 0;
    if (PAL_GET_TYPE(handle) == pal_type_pipeprv)
        attr->writeable = handle->hdr.flags & WRITEABLE(1);
    else
        attr->writeable = handle->hdr.flags & WRITEABLE(0);
    attr->pending_size = val;
    return 0;
}

static int pipe_attrsetbyhdl (PAL_HANDLE handle, PAL_STREAM_ATTR * attr)
{
    if (handle->hdr.fds[0] == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    int ret;
    PAL_BOL * nonblocking = (handle->hdr.type == pal_type_pipeprv) ?
                            &handle->pipeprv.nonblocking :
                            &handle->pipe.nonblocking;

    if (attr->nonblocking != *nonblocking) {
        ret = INLINE_SYSCALL(fcntl, 3, handle->hdr.fds[0], F_SETFL,
                             *nonblocking ? O_NONBLOCK : 0);

        if (IS_ERR(ret))
            return unix_to_pal_error(ERRNO(ret));

        *nonblocking = attr->nonblocking;
    }

    return 0;
}

static int pipe_getname (PAL_HANDLE handle, char * buffer, int count)
{
    int old_count = count;
    int ret;

    const char * prefix = NULL;
    int prefix_len = 0;

    switch (PAL_GET_TYPE(handle)) {
        case pal_type_pipesrv:
        case pal_type_pipecli:
            prefix_len = 8;
            prefix = "pipe.srv";
            break;
        case pal_type_pipe:
            prefix_len = 4;
            prefix = "pipe";
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
    count  -= prefix_len + 1;

    ret = snprintf(buffer, count, "%lu\n", handle->pipe.pipeid);

    if (buffer[ret - 1] != '\n') {
        memset(buffer, 0, count);
        return -PAL_ERROR_OVERFLOW;
    }

    buffer[ret - 1] = 0;
    buffer += ret - 1;
    count  -= ret - 1;
    return old_count - count;
}

struct handle_ops pipe_ops = {
        .getname            = &pipe_getname,
        .open               = &pipe_open,
        .waitforclient      = &pipe_waitforclient,
        .read               = &pipe_read,
        .write              = &pipe_write,
        .close              = &pipe_close,
        .delete             = &pipe_delete,
        .attrquerybyhdl     = &pipe_attrquerybyhdl,
        .attrsetbyhdl       = &pipe_attrsetbyhdl,
    };

struct handle_ops pipeprv_ops = {
        .open               = &pipe_open,
        .read               = &pipe_read,
        .write              = &pipe_write,
        .close              = &pipe_close,
        .attrquerybyhdl     = &pipe_attrquerybyhdl,
        .attrsetbyhdl       = &pipe_attrsetbyhdl,
    };
