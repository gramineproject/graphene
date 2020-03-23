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

#include "api.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_linux_error.h"
#include "pal_security.h"

typedef __kernel_pid_t pid_t;
#include <asm/fcntl.h>
#include <asm/poll.h>
#include <linux/types.h>
#include <linux/un.h>

static int pipe_addr(int pipeid, struct sockaddr_un* addr) {
    /* use abstract UNIX sockets for pipes, with name format "@/graphene/12345678" */
    addr->sun_family = AF_UNIX;
    memset(addr->sun_path, 0, sizeof(addr->sun_path));

    /* for abstract sockets, first char is NUL */
    char* str   = (char*)addr->sun_path + 1;
    size_t size = sizeof(addr->sun_path) - 1;

    /* pipe_prefix already contains a slash at the end, so not needed in the format string */
    int ret = snprintf(str, size, "%s%08x", pal_sec.pipe_prefix, pipeid);
    return ret >= 0 && (size_t)ret < size ? 0 : -EINVAL;
}

/*!
 * \brief Create a listening abstract UNIX socket as preparation for connecting two ends of a pipe.
 *
 * An abstract UNIX socket with name "@/graphene/<pipeid>" is opened for listening. A corresponding
 * PAL handle with type `pipesrv` is created. This PAL handle typically serves only as an
 * intermediate step to connect two ends of the pipe (`pipecli` and `pipe`). As soon as the other
 * end of the pipe connects to this listening socket, a new accepted socket and the corresponding
 * PAL handle are created, and this `pipesrv` handle can be closed.
 *
 * \param[out] handle  PAL handle of type `pipesrv` with abstract UNIX socket opened for listening.
 * \param[in]  pipeid  Integer uniquely identifying the pipe.
 * \param[in]  options May contain PAL_OPTION_NONBLOCK.
 * \return             0 on success, negative PAL error code otherwise.
 */
static int pipe_listen(PAL_HANDLE* handle, PAL_NUM pipeid, int options) {
    int ret;

    struct sockaddr_un addr;
    ret = pipe_addr(pipeid, &addr);
    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    struct sockopt sock_options;
    unsigned int addrlen = sizeof(struct sockaddr_un);
    int nonblock = options & PAL_OPTION_NONBLOCK ? SOCK_NONBLOCK : 0;

    ret = ocall_listen(AF_UNIX, SOCK_STREAM | nonblock, 0, /*ipv6_v6only=*/0,
                       (struct sockaddr*)&addr, &addrlen, &sock_options);
    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    PAL_HANDLE hdl = malloc(HANDLE_SIZE(pipe));
    if (!hdl) {
        ocall_close(ret);
        return -PAL_ERROR_NOMEM;
    }

    SET_HANDLE_TYPE(hdl, pipesrv);
    HANDLE_HDR(hdl)->flags |= RFD(0);  /* cannot write to a listening socket */
    hdl->pipe.fd            = ret;
    hdl->pipe.pipeid        = pipeid;
    hdl->pipe.nonblocking   = options & PAL_OPTION_NONBLOCK ? PAL_TRUE : PAL_FALSE;

    *handle = hdl;
    return 0;
}

/*!
 * \brief Accept the other end of the pipe and create PAL handle for our end of the pipe.
 *
 * Caller creates a `pipesrv` PAL handle with the underlying abstract UNIX socket opened for
 * listening, and then calls this function to wait for the other end of the pipe to connect.
 * When the connection request arrives, a new `pipecli` PAL handle is created with the
 * corresponding underlying socket and is returned in `client`. This `pipecli` PAL handle denotes
 * our end of the pipe. Typically, `pipesrv` handle is not needed after this and can be closed.
 *
 * \param[in]  handle  PAL handle of type `pipesrv` with abstract UNIX socket opened for listening.
 * \param[out] client  PAL handle of type `pipecli` connected to the other end of the pipe (`pipe`).
 * \return             0 on success, negative PAL error code otherwise.
 */
static int pipe_waitforclient(PAL_HANDLE handle, PAL_HANDLE* client) {
    if (!IS_HANDLE_TYPE(handle, pipesrv))
        return -PAL_ERROR_NOTSERVER;

    if (handle->pipe.fd == PAL_IDX_POISON)
        return -PAL_ERROR_DENIED;

    struct sockopt sock_options;
    int ret = ocall_accept(handle->pipe.fd, NULL, NULL, &sock_options);
    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    PAL_HANDLE clnt = malloc(HANDLE_SIZE(pipe));
    if (!clnt) {
        ocall_close(ret);
        return -PAL_ERROR_NOMEM;
    }

    SET_HANDLE_TYPE(clnt, pipecli);
    HANDLE_HDR(clnt)->flags |= RFD(0) | WFD(0);
    clnt->pipe.fd            = ret;
    clnt->pipe.nonblocking   = PAL_FALSE; /* FIXME: must set nonblocking based on `handle` value */
    clnt->pipe.pipeid        = handle->pipe.pipeid;

    *client = clnt;
    return 0;
}

/*!
 * \brief Connect to the other end of the pipe and create PAL handle for our end of the pipe.
 *
 * This function connects to the other end of the pipe, represented as an abstract UNIX socket
 * "@/graphene/<pipeid>" opened for listening. When the connection succeeds, a new `pipe` PAL handle
 * is created with the corresponding underlying socket and is returned in `handle`. The other end of
 * the pipe is typically of type `pipecli`.
 *
 * \param[out] handle  PAL handle of type `pipe` with abstract UNIX socket connected to another end.
 * \param[in]  pipeid  Integer uniquely identifying the pipe.
 * \param[in]  options May contain PAL_OPTION_NONBLOCK.
 * \return             0 on success, negative PAL error code otherwise.
 */
static int pipe_connect(PAL_HANDLE* handle, PAL_NUM pipeid, int options) {
    int ret;

    struct sockaddr_un addr;
    ret = pipe_addr(pipeid, &addr);
    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    struct sockopt sock_options;
    unsigned int addrlen = sizeof(struct sockaddr_un);
    int nonblock = options & PAL_OPTION_NONBLOCK ? SOCK_NONBLOCK : 0;

    ret = ocall_connect(AF_UNIX, SOCK_STREAM | nonblock, 0, /*ipv6_v6only=*/0,
                        (const struct sockaddr*)&addr,
                        addrlen, NULL, NULL, &sock_options);
    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    PAL_HANDLE hdl = malloc(HANDLE_SIZE(pipe));
    if (!hdl) {
        ocall_close(ret);
        return -PAL_ERROR_NOMEM;
    }

    SET_HANDLE_TYPE(hdl, pipe);
    HANDLE_HDR(hdl)->flags |= RFD(0) | WFD(0);
    hdl->pipe.fd            = ret;
    hdl->pipe.pipeid        = pipeid;
    hdl->pipe.nonblocking   = (options & PAL_OPTION_NONBLOCK) ? PAL_TRUE : PAL_FALSE;

    *handle = hdl;
    return 0;
}

/*!
 * \brief Create PAL handle with read and write ends of a pipe.
 *
 * This function creates a PAL handle of type `pipeprv` (anonymous pipe). In contrast to other types
 * of pipes, `pipeprv` encapsulates both ends of the pipe, backed by a host-level socketpair. This
 * type of pipe is typically reserved for internal PAL uses, not for LibOS emulation.
 *
 * \param[out] handle  PAL handle of type `pipeprv` backed by a host-level socketpair.
 * \param[in]  options May contain PAL_OPTION_NONBLOCK.
 * \return             0 on success, negative PAL error code otherwise.
 */
static int pipe_private(PAL_HANDLE* handle, int options) {
    int fds[2];

    int nonblock = options & PAL_OPTION_NONBLOCK ? SOCK_NONBLOCK : 0;

    int ret = ocall_socketpair(AF_UNIX, SOCK_STREAM | nonblock, 0, fds);
    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    PAL_HANDLE hdl = malloc(HANDLE_SIZE(pipeprv));
    if (!hdl) {
        ocall_close(fds[0]);
        ocall_close(fds[1]);
        return -PAL_ERROR_NOMEM;
    }

    SET_HANDLE_TYPE(hdl, pipeprv);
    HANDLE_HDR(hdl)->flags  |= RFD(0) | WFD(1); /* first FD for reads, second FD for writes */
    hdl->pipeprv.fds[0]      = fds[0];
    hdl->pipeprv.fds[1]      = fds[1];
    hdl->pipeprv.nonblocking = (options & PAL_OPTION_NONBLOCK) ? PAL_TRUE : PAL_FALSE;

    *handle = hdl;
    return 0;
}

/*!
 * \brief Create PAL handle of type `pipeprv`, `pipesrv`, or `pipe` depending on `type` and `uri`.
 *
 * Depending on the combination of `type` and `uri`, the following PAL handles are created:
 *
 * - `type` is URI_TYPE_PIPE and `url` is empty: create `pipeprv` handle (with two connected
 *                                               ends of an anonymous pipe).
 *
 * - `type` is URI_TYPE_PIPE_SRV: create `pipesrv` handle (intermediate listening socket) with
 *                                name in the form of "@/graphene/<pipeid>" where pipeid is
 *                                derived from `uri` via strtol(). Caller is expected to call
 *                                pipe_waitforclient() afterwards.
 *
 * - `type` is URI_TYPE_PIPE: create `pipe` handle (connecting socket) with name in the form of
 *                            "@/graphene/<pipeid>" where pipeid is derived from `uri` via
 *                            strtol().
 *
 * \param[out] handle  Created PAL handle of type `pipeprv`, `pipesrv`, or `pipe`.
 * \param[in]  type    Can be URI_TYPE_PIPE or URI_TYPE_PIPE_SRV.
 * \param[in]  uri     Content is either NUL (for anonymous pipe) or an integer denoting pipeid.
 * \param[in]  access  Not used.
 * \param[in]  share   Not used.
 * \param[in]  create  Not used.
 * \param[in]  options May contain PAL_OPTION_NONBLOCK.
 * \return             0 on success, negative PAL error code otherwise.
 */
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

/*!
 * \brief Read from pipe (from read end in case of `pipeprv`).
 *
 * \param[in]  handle  PAL handle of type `pipeprv`, `pipecli`, or `pipe`.
 * \param[in]  offset  Not used.
 * \param[in]  len     Size of user-supplied buffer.
 * \param[out] buffer  User-supplied buffer to read data to.
 * \return             Number of bytes read on success, negative PAL error code otherwise.
 */
static int64_t pipe_read(PAL_HANDLE handle, uint64_t offset, uint64_t len, void* buffer) {
    if (offset)
        return -PAL_ERROR_INVAL;

    if (!IS_HANDLE_TYPE(handle, pipecli) && !IS_HANDLE_TYPE(handle, pipeprv) &&
        !IS_HANDLE_TYPE(handle, pipe))
        return -PAL_ERROR_NOTCONNECTION;

    int fd = IS_HANDLE_TYPE(handle, pipeprv) ? handle->pipeprv.fds[0] : handle->pipe.fd;

    ssize_t bytes = ocall_recv(fd, buffer, len, NULL, NULL, NULL, NULL);
    if (IS_ERR(bytes))
        return unix_to_pal_error(ERRNO(bytes));

    if (!bytes)
        return -PAL_ERROR_ENDOFSTREAM;

    return bytes;
}

/*!
 * \brief Write to pipe (to write end in case of `pipeprv`).
 *
 * \param[in] handle  PAL handle of type `pipeprv`, `pipecli`, or `pipe`.
 * \param[in] offset  Not used.
 * \param[in] len     Size of user-supplied buffer.
 * \param[in] buffer  User-supplied buffer to write data from.
 * \return            Number of bytes written on success, negative PAL error code otherwise.
 */
static int64_t pipe_write(PAL_HANDLE handle, uint64_t offset, uint64_t len, const void* buffer) {
    if (offset)
        return -PAL_ERROR_INVAL;

    if (!IS_HANDLE_TYPE(handle, pipecli) && !IS_HANDLE_TYPE(handle, pipeprv) &&
        !IS_HANDLE_TYPE(handle, pipe))
        return -PAL_ERROR_NOTCONNECTION;

    int fd = IS_HANDLE_TYPE(handle, pipeprv) ? handle->pipeprv.fds[1] : handle->pipe.fd;

    ssize_t bytes = ocall_send(fd, buffer, len, NULL, 0, NULL, 0);
    if (IS_ERR(bytes))
        return unix_to_pal_error(ERRNO(bytes));

    return bytes;
}

/*!
 * \brief Close pipe (both ends in case of `pipeprv`).
 *
 * \param[in] handle  PAL handle of type `pipeprv`, `pipesrv`, `pipecli`, or `pipe`.
 * \return            0 on success, negative PAL error code otherwise.
 */
static int pipe_close(PAL_HANDLE handle) {
    if (IS_HANDLE_TYPE(handle, pipeprv)) {
        if (handle->pipeprv.fds[0] != PAL_IDX_POISON) {
            ocall_close(handle->pipeprv.fds[0]);
            handle->pipeprv.fds[0] = PAL_IDX_POISON;
        }
        if (handle->pipeprv.fds[1] != PAL_IDX_POISON) {
            ocall_close(handle->pipeprv.fds[1]);
            handle->pipeprv.fds[1] = PAL_IDX_POISON;
        }
    } else if (handle->pipe.fd != PAL_IDX_POISON) {
        ocall_close(handle->pipe.fd);
        handle->pipe.fd = PAL_IDX_POISON;
    }

    return 0;
}

/*!
 * \brief Shut down pipe (one or both ends in case of `pipeprv` depending on `access`).
 *
 * \param[in] handle  PAL handle of type `pipeprv`, `pipesrv`, `pipecli`, or `pipe`.
 * \param[in] access  May be 0, PAL_DELETE_RD, PAL_DELETE_WR.
 * \return            0 on success, negative PAL error code otherwise.
 */
static int pipe_delete(PAL_HANDLE handle, int access) {
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

    if (IS_HANDLE_TYPE(handle, pipeprv)) {
        /* pipeprv has two underlying FDs, shut down the requested one(s) */
        if (handle->pipeprv.fds[0] != PAL_IDX_POISON &&
            (shutdown == SHUT_RD || shutdown == SHUT_RDWR)) {
            ocall_shutdown(handle->pipeprv.fds[0], SHUT_RD);
        }

        if (handle->pipeprv.fds[1] != PAL_IDX_POISON &&
            (shutdown == SHUT_WR || shutdown == SHUT_RDWR)) {
            ocall_shutdown(handle->pipeprv.fds[1], SHUT_WR);
        }
    } else {
        /* other types of pipes have a single underlying FD, shut it down */
        if (handle->pipe.fd != PAL_IDX_POISON) {
            ocall_shutdown(handle->pipe.fd, shutdown);
        }
    }

    return 0;
}

/*!
 * \brief Retrieve attributes of PAL handle.
 *
 * \param[in]  handle  PAL handle of type `pipeprv`, `pipesrv`, `pipecli`, or `pipe`.
 * \param[out] attr    User-supplied buffer to store handle's current attributes.
 * \return             0 on success, negative PAL error code otherwise.
 */
static int pipe_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    int ret;

    if (handle->pipe.fd == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    attr->handle_type  = HANDLE_HDR(handle)->type;
    attr->nonblocking  = IS_HANDLE_TYPE(handle, pipeprv) ? handle->pipeprv.nonblocking
                                                         : handle->pipe.nonblocking;
    attr->disconnected = HANDLE_HDR(handle)->flags & ERROR(0);

    /* get number of bytes available for reading (doesn't make sense for "listening" pipes) */
    attr->pending_size = 0;
    if (!IS_HANDLE_TYPE(handle, pipesrv)) {
        ret = ocall_fionread(handle->pipe.fd);
        if (IS_ERR(ret))
            return unix_to_pal_error(ERRNO(ret));

        attr->pending_size = ret;
    }

    /* query if there is data available for reading/writing */
    if (IS_HANDLE_TYPE(handle, pipeprv)) {
        /* for private pipe, readable and writable are queried on different fds */
        struct pollfd pfd[2] = {{.fd = handle->pipeprv.fds[0], .events = POLLIN,  .revents = 0},
                                {.fd = handle->pipeprv.fds[1], .events = POLLOUT, .revents = 0}};
        ret = ocall_poll(&pfd[0], 2, 0);
        if (IS_ERR(ret))
            return unix_to_pal_error(ERRNO(ret));

        attr->readable = ret >= 1 && (pfd[0].revents & (POLLIN | POLLERR | POLLHUP)) == POLLIN;
        attr->writable = ret >= 1 && (pfd[1].revents & (POLLOUT | POLLERR | POLLHUP)) == POLLOUT;
    } else {
        /* for non-private pipes, both readable and writable are queried on the same fd */
        short pfd_events = POLLIN;
        if (!IS_HANDLE_TYPE(handle, pipesrv)) {
            /* querying for writing doesn't make sense for "listening" pipes */
            pfd_events |= POLLOUT;
        }

        struct pollfd pfd = {.fd = handle->pipe.fd, .events = pfd_events, .revents = 0};
        ret = ocall_poll(&pfd, 1, 0);
        if (IS_ERR(ret))
            return unix_to_pal_error(ERRNO(ret));

        attr->readable = ret == 1 && (pfd.revents & (POLLIN | POLLERR | POLLHUP)) == POLLIN;
        attr->writable = ret == 1 && (pfd.revents & (POLLOUT | POLLERR | POLLHUP)) == POLLOUT;
    }

    return 0;
}

/*!
 * \brief Set attributes of PAL handle.
 *
 * Currently only `nonblocking` attribute can be set.
 *
 * \param[in] handle  PAL handle of type `pipeprv`, `pipesrv`, `pipecli`, or `pipe`.
 * \param[in] attr    User-supplied buffer with new handle's attributes.
 * \return            0 on success, negative PAL error code otherwise.
 */
static int pipe_attrsetbyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    if (handle->generic.fds[0] == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    PAL_BOL* nonblocking = (HANDLE_HDR(handle)->type == pal_type_pipeprv)
                               ? &handle->pipeprv.nonblocking
                               : &handle->pipe.nonblocking;

    if (attr->nonblocking != *nonblocking) {
        int ret = ocall_fsetnonblock(handle->generic.fds[0], attr->nonblocking);
        if (IS_ERR(ret))
            return unix_to_pal_error(ERRNO(ret));

        *nonblocking = attr->nonblocking;
    }

    return 0;
}

/*!
 * \brief Retrieve full URI of PAL handle.
 *
 * Full URI is composed of the type and pipeid: "<type>:<pipeid>".
 *
 * \param[in]  handle  PAL handle of type `pipeprv`, `pipesrv`, `pipecli`, or `pipe`.
 * \param[out] buffer  User-supplied buffer to write URI to.
 * \param[in]  count   Size of the user-supplied buffer.
 * \return             Number of bytes written on success, negative PAL error code otherwise.
 */
static int pipe_getname(PAL_HANDLE handle, char* buffer, size_t count) {
    size_t old_count = count;
    int ret;

    const char* prefix = NULL;
    size_t prefix_len  = 0;

    switch (HANDLE_TYPE(handle)) {
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
