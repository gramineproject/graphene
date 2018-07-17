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
#include "pal_linux_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_error.h"
#include "pal_security.h"
#include "pal_debug.h"
#include "api.h"

#include <linux/types.h>
typedef __kernel_pid_t pid_t;
#include <asm/fcntl.h>
#include <asm/poll.h>
#include <linux/un.h>

static int pipe_path (int pipeid, char * path, int len)
{
    /* use abstrace UNIX sockets for pipes */
    memset(path, 0, len);
    return snprintf(path + 1, len - 1, "%s%08x", pal_sec.pipe_prefix, pipeid);
}

static int pipe_addr (int pipeid, struct sockaddr_un * addr)
{
    addr->sun_family = AF_UNIX;
    return pipe_path(pipeid, (char *) addr->sun_path, sizeof(addr->sun_path));
}

static inline int pipe_type (int options)
{
    int type = SOCK_STREAM;
    if (options & PAL_OPTION_NONBLOCK)
        type |= SOCK_NONBLOCK;
    return type;
}

static int pipe_listen (PAL_HANDLE * handle, PAL_NUM pipeid, int options)
{
    struct sockaddr_un addr;
    int ret;

    if ((ret = pipe_addr(pipeid, &addr)) < 0)
        return ret;

    unsigned int addrlen = sizeof(struct sockaddr_un);
    struct sockopt sock_options;
    ret = ocall_sock_listen(AF_UNIX, pipe_type(options), 0,
                            (struct sockaddr *) &addr, &addrlen,
                            &sock_options);
    if (ret < 0)
        return ret;

    PAL_HANDLE hdl = malloc(HANDLE_SIZE(pipe));
    SET_HANDLE_TYPE(hdl, pipesrv);
    HANDLE_HDR(hdl)->flags |= RFD(0);
    hdl->pipe.fd = ret;
    hdl->pipe.pipeid = pipeid;
    hdl->pipe.nonblocking = options & PAL_OPTION_NONBLOCK ?
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

    struct sockopt sock_options;
    int ret = ocall_sock_accept(handle->pipe.fd, NULL, NULL, &sock_options);
    if (ret < 0)
        return ret;

    PAL_HANDLE clnt = malloc(HANDLE_SIZE(pipe));
    SET_HANDLE_TYPE(clnt, pipecli);
    HANDLE_HDR(clnt)->flags |= RFD(0)|WFD(0)|WRITEABLE(0);
    clnt->pipe.fd = ret;
    clnt->pipe.nonblocking = PAL_FALSE;
    clnt->pipe.pipeid = handle->pipe.pipeid;
    *client = clnt;

    return 0;
}

static int pipe_connect (PAL_HANDLE * handle, PAL_NUM pipeid, int options)
{
    struct sockaddr_un addr;
    int ret;

    if ((ret = pipe_addr(pipeid, &addr)) < 0)
        return ret;

    struct sockopt sock_options;
    ret = ocall_sock_connect(AF_UNIX, pipe_type(options), 0,
                             (void *) &addr, sizeof(struct sockaddr_un),
                             NULL, NULL, &sock_options);
    if (ret < 0)
        return ret;

    PAL_HANDLE hdl = malloc(HANDLE_SIZE(pipe));
    SET_HANDLE_TYPE(hdl, pipe);
    HANDLE_HDR(hdl)->flags |= RFD(0)|WFD(0)|WRITEABLE(0);
    hdl->pipe.fd = ret;
    hdl->pipe.pipeid = pipeid;
    hdl->pipe.nonblocking = (options & PAL_OPTION_NONBLOCK) ?
                            PAL_TRUE : PAL_FALSE;
    *handle = hdl;

    return 0;
}

static int pipe_private (PAL_HANDLE * handle, int options)
{
    int ret, fds[2];
    int type = SOCK_STREAM;
    if (options & PAL_OPTION_NONBLOCK)
        type |= SOCK_NONBLOCK;

    ret = ocall_socketpair(AF_UNIX, type, 0, fds);
    if (ret < 0)
        return ret;

    PAL_HANDLE hdl = malloc(HANDLE_SIZE(pipeprv));
    SET_HANDLE_TYPE(hdl, pipeprv);
    HANDLE_HDR(hdl)->flags |= RFD(0)|WFD(1)|WRITEABLE(1);
    hdl->pipeprv.fds[0] = fds[0];
    hdl->pipeprv.fds[1] = fds[1];
    hdl->pipeprv.nonblocking = (options & PAL_OPTION_NONBLOCK) ?
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
    options &= PAL_OPTION_MASK;

    if (strpartcmp_static(type, "pipe:") && !*uri)
        return pipe_private(handle, options);

    char * endptr;
    PAL_NUM pipeid = strtol(uri, &endptr, 10);

    if (*endptr)
        return -PAL_ERROR_INVAL;

    if (strpartcmp_static(type, "pipe.srv:"))
        return pipe_listen(handle, pipeid, options);

    if (strpartcmp_static(type, "pipe:"))
        return pipe_connect(handle, pipeid, options);

    return -PAL_ERROR_INVAL;
}

/* 'read' operation of pipe stream. offset does not apply here. */
static int64_t pipe_read (PAL_HANDLE handle, uint64_t offset, uint64_t len,
                          void * buffer)
{
    if (!IS_HANDLE_TYPE(handle, pipecli) &&
        !IS_HANDLE_TYPE(handle, pipeprv) &&
        !IS_HANDLE_TYPE(handle, pipe))
        return -PAL_ERROR_NOTCONNECTION;

    if (len >= (1ULL << (sizeof(unsigned int) * 8)))
        return -PAL_ERROR_INVAL;

    int fd = IS_HANDLE_TYPE(handle, pipeprv) ? handle->pipeprv.fds[0] :
             handle->pipe.fd;
    int bytes = ocall_sock_recv(fd, buffer, len, NULL, NULL);

    if (bytes < 0)
        return bytes;

    if (!bytes)
        return -PAL_ERROR_ENDOFSTREAM;

    return bytes;
}

/* 'write' operation of pipe stream. offset does not apply here. */
static int64_t pipe_write (PAL_HANDLE handle, uint64_t offset, uint64_t len,
                           const void * buffer)
{
    if (!IS_HANDLE_TYPE(handle, pipecli) &&
        !IS_HANDLE_TYPE(handle, pipeprv) &&
        !IS_HANDLE_TYPE(handle, pipe))
        return -PAL_ERROR_NOTCONNECTION;

    if (len >= (1ULL << (sizeof(unsigned int) * 8)))
        return -PAL_ERROR_INVAL;

    int fd = IS_HANDLE_TYPE(handle, pipeprv) ? handle->pipeprv.fds[1] :
             handle->pipe.fd;
    int bytes = ocall_sock_send(fd, buffer, len, NULL, 0);

    PAL_FLG writeable = IS_HANDLE_TYPE(handle, pipeprv) ? WRITEABLE(1) :
                        WRITEABLE(0);

    if (bytes == -PAL_ERROR_TRYAGAIN)
        HANDLE_HDR(handle)->flags &= ~writeable;

    if (bytes < 0)
        return bytes;

    if (bytes == len)
        HANDLE_HDR(handle)->flags |= writeable;
    else
        HANDLE_HDR(handle)->flags &= ~writeable;

    return bytes;
}

/* 'close' operation of pipe stream. */
static int pipe_close (PAL_HANDLE handle)
{
    if (IS_HANDLE_TYPE(handle, pipeprv)) {
        if (handle->pipeprv.fds[0] != PAL_IDX_POISON) {
            ocall_close(handle->pipeprv.fds[0]);
            handle->pipeprv.fds[0] = PAL_IDX_POISON;
        }
        if (handle->pipeprv.fds[1] != PAL_IDX_POISON) {
            ocall_close(handle->pipeprv.fds[1]);
            handle->pipeprv.fds[1] = PAL_IDX_POISON;
        }
        return 0;
    }

    if (handle->pipe.fd != PAL_IDX_POISON) {
        ocall_close(handle->pipe.fd);
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
                    ocall_close(handle->pipeprv.fds[0]);
                    handle->pipeprv.fds[0] = PAL_IDX_POISON;
                }
                if (handle->pipeprv.fds[1] != PAL_IDX_POISON) {
                    ocall_close(handle->pipeprv.fds[1]);
                    handle->pipeprv.fds[1] = PAL_IDX_POISON;
                }
                break;
            case PAL_DELETE_RD:
                if (handle->pipeprv.fds[0] != PAL_IDX_POISON) {
                    ocall_close(handle->pipeprv.fds[0]);
                    handle->pipeprv.fds[0] = PAL_IDX_POISON;
                }
                break;
            case PAL_DELETE_WR:
                if (handle->pipeprv.fds[1] != PAL_IDX_POISON) {
                    ocall_close(handle->pipeprv.fds[1]);
                    handle->pipeprv.fds[1] = PAL_IDX_POISON;
                }
                break;
            default:
                return -PAL_ERROR_INVAL;
        }
    }

    if (IS_HANDLE_TYPE(handle, pipesrv)) {
        char buffer[108];
        pipe_path(handle->pipe.pipeid, buffer, 108);
        ocall_delete(buffer);
        return 0;
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

    ocall_sock_shutdown(handle->pipe.fd, shutdown);
    return 0;
}

static int pipe_attrquerybyhdl (PAL_HANDLE handle, PAL_STREAM_ATTR * attr)
{
    if (handle->generic.fds[0] == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    attr->handle_type  = PAL_GET_TYPE(handle);

    int read_fd = handle->generic.fds[0];
    int flags = HANDLE_HDR(handle)->flags;

    if (!IS_HANDLE_TYPE(handle, pipesrv)) {
        int ret = ocall_fionread(read_fd);
        if (ret < 0)
            return -ret;

        attr->pending_size = ret;
        attr->writeable    = flags & (
            IS_HANDLE_TYPE(handle, pipeprv) ? WRITEABLE(1) : WRITEABLE(0));
    } else {
        attr->pending_size = 0;
        attr->writeable    = PAL_FALSE;
    }

    struct pollfd pfd = { .fd = read_fd, .events = POLLIN, .revents = 0 };
    unsigned long waittime = 0;
    int ret = ocall_poll(&pfd, 1, &waittime);
    if (ret < 0)
        return ret;
    
    attr->readable = (ret == 1 && pfd.revents == POLLIN);

    attr->disconnected = flags & ERROR(0);
    attr->nonblocking  = IS_HANDLE_TYPE(handle, pipeprv) ?
                         handle->pipeprv.nonblocking : handle->pipe.nonblocking;

    return 0;
}

static int pipe_attrsetbyhdl (PAL_HANDLE handle, PAL_STREAM_ATTR * attr)
{
    if (handle->generic.fds[0] == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    PAL_BOL * nonblocking = (HANDLE_HDR(handle)->type == pal_type_pipeprv) ?
                            &handle->pipeprv.nonblocking :
                            &handle->pipe.nonblocking;

    if (attr->nonblocking != *nonblocking) {
        int ret = ocall_fsetnonblock(handle->generic.fds[0], attr->nonblocking);
        if (ret < 0)
            return ret;

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

    switch (HANDLE_TYPE(handle)) {
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
