/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains operands to handle streams with URIs that start with "pipe:" or "pipe.srv:".
 */

#include <asm/fcntl.h>
#include <asm/poll.h>
#include <linux/types.h>
#include <linux/un.h>

#include "api.h"
#include "cpu.h"
#include "crypto.h"
#include "linux_utils.h"
#include "pal.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_linux_error.h"
#include "pal_security.h"

static int pipe_session_key(PAL_PIPE_NAME* name, PAL_SESSION_KEY* session_key) {
    return lib_HKDF_SHA256((uint8_t*)&g_master_key, sizeof(g_master_key), /*salt=*/NULL,
                           /*salt_size=*/0, (uint8_t*)name->str, sizeof(name->str),
                           (uint8_t*)session_key, sizeof(*session_key));
}

static int thread_handshake_func(void* param) {
    PAL_HANDLE handle = (PAL_HANDLE)param;

    assert(handle);
    assert(HANDLE_HDR(handle)->type == PAL_TYPE_PIPE);
    assert(!handle->pipe.ssl_ctx);
    assert(!handle->pipe.handshake_done);

    int ret = _DkStreamSecureInit(handle, handle->pipe.is_server, &handle->pipe.session_key,
                                  (LIB_SSL_CONTEXT**)&handle->pipe.ssl_ctx, NULL, 0);
    if (ret < 0) {
        log_error("Failed to initialize secure pipe %s: %d", handle->pipe.name.str, ret);
        _DkProcessExit(1);
    }

    __atomic_store_n(&handle->pipe.handshake_done, 1, __ATOMIC_RELEASE);
    return 0;
}

/*!
 * \brief Create a listening abstract UNIX socket as preparation for connecting two ends of a pipe.
 *
 * An abstract UNIX socket with name "/graphene/<instance_id>/<pipename>" is opened for listening. A
 * corresponding PAL handle with type `pipesrv` is created. This PAL handle typically serves only as
 * an intermediate step to connect two ends of the pipe (`pipecli` and `pipe`). As soon as the other
 * end of the pipe connects to this listening socket, a new accepted socket and the corresponding
 * PAL handle are created, and this `pipesrv` handle can be closed.
 *
 * \param[out] handle  PAL handle of type `pipesrv` with abstract UNIX socket opened for listening.
 * \param[in]  name    String uniquely identifying the pipe.
 * \param[in]  options May contain PAL_OPTION_NONBLOCK.
 * \return             0 on success, negative PAL error code otherwise.
 */
static int pipe_listen(PAL_HANDLE* handle, const char* name, int options) {
    int ret;

    struct sockaddr_un addr;
    ret = get_graphene_unix_socket_addr(g_pal_state.instance_id, name, &addr);
    if (ret < 0)
        return -PAL_ERROR_DENIED;

    struct sockopt sock_options;
    size_t addrlen = sizeof(struct sockaddr_un);
    int nonblock = options & PAL_OPTION_NONBLOCK ? SOCK_NONBLOCK : 0;

    ret = ocall_listen(AF_UNIX, SOCK_STREAM | nonblock, 0, /*ipv6_v6only=*/0,
                       (struct sockaddr*)&addr, &addrlen, &sock_options);
    if (ret < 0)
        return unix_to_pal_error(ret);

    PAL_HANDLE hdl = malloc(HANDLE_SIZE(pipe));
    if (!hdl) {
        ocall_close(ret);
        return -PAL_ERROR_NOMEM;
    }

    init_handle_hdr(HANDLE_HDR(hdl), PAL_TYPE_PIPESRV);
    HANDLE_HDR(hdl)->flags |= RFD(0); /* cannot write to a listening socket */
    hdl->pipe.fd          = ret;
    hdl->pipe.nonblocking = options & PAL_OPTION_NONBLOCK ? PAL_TRUE : PAL_FALSE;

    /* padding with zeros is because the whole buffer is used in key derivation */
    memset(&hdl->pipe.name.str, 0, sizeof(hdl->pipe.name.str));
    memcpy(&hdl->pipe.name.str, name, strlen(name) + 1);

    /* pipesrv handle is only intermediate so it doesn't need SSL context or session key */
    hdl->pipe.ssl_ctx        = NULL;
    hdl->pipe.is_server      = false;
    hdl->pipe.handshake_done = 1; /* pipesrv doesn't do any handshake so consider it done */
    memset(hdl->pipe.session_key, 0, sizeof(hdl->pipe.session_key));

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
    if (HANDLE_HDR(handle)->type != PAL_TYPE_PIPESRV)
        return -PAL_ERROR_NOTSERVER;

    if (handle->pipe.fd == PAL_IDX_POISON)
        return -PAL_ERROR_DENIED;

    struct sockopt sock_options;
    int ret = ocall_accept(handle->pipe.fd, NULL, NULL, &sock_options);
    if (ret < 0)
        return unix_to_pal_error(ret);

    PAL_HANDLE clnt = malloc(HANDLE_SIZE(pipe));
    if (!clnt) {
        ocall_close(ret);
        return -PAL_ERROR_NOMEM;
    }

    init_handle_hdr(HANDLE_HDR(clnt), PAL_TYPE_PIPECLI);
    HANDLE_HDR(clnt)->flags |= RFD(0) | WFD(0);
    clnt->pipe.fd          = ret;
    clnt->pipe.name        = handle->pipe.name;
    clnt->pipe.nonblocking = PAL_FALSE; /* FIXME: must set nonblocking based on `handle` value */

    /* create the SSL pre-shared key for this end of the pipe; note that SSL context is initialized
     * lazily on first read/write on this pipe */
    clnt->pipe.ssl_ctx        = NULL;
    clnt->pipe.is_server      = false;
    clnt->pipe.handshake_done = 0;

    ret = pipe_session_key(&clnt->pipe.name, &clnt->pipe.session_key);
    if (ret < 0) {
        ocall_close(clnt->pipe.fd);
        free(clnt);
        return -PAL_ERROR_DENIED;
    }

    ret = _DkStreamSecureInit(clnt, clnt->pipe.is_server, &clnt->pipe.session_key,
                              (LIB_SSL_CONTEXT**)&clnt->pipe.ssl_ctx, NULL, 0);
    if (ret < 0) {
        ocall_close(clnt->pipe.fd);
        free(clnt);
        return ret;
    }
    __atomic_store_n(&clnt->pipe.handshake_done, 1, __ATOMIC_RELEASE);

    *client = clnt;
    return 0;
}

/*!
 * \brief Connect to the other end of the pipe and create PAL handle for our end of the pipe.
 *
 * This function connects to the other end of the pipe, represented as an abstract UNIX socket
 * "/graphene/<instance_id>/<pipename>" opened for listening. When the connection succeeds, a new
 * `pipe` PAL handle is created with the corresponding underlying socket and is returned in
 * `handle`. The other end of the pipe is typically of type `pipecli`.
 *
 * \param[out] handle  PAL handle of type `pipe` with abstract UNIX socket connected to another end.
 * \param[in]  name    String uniquely identifying the pipe.
 * \param[in]  options May contain PAL_OPTION_NONBLOCK.
 * \return             0 on success, negative PAL error code otherwise.
 */
static int pipe_connect(PAL_HANDLE* handle, const char* name, int options) {
    int ret;

    struct sockaddr_un addr;
    ret = get_graphene_unix_socket_addr(g_pal_state.instance_id, name, &addr);
    if (ret < 0)
        return -PAL_ERROR_DENIED;

    struct sockopt sock_options;
    unsigned int addrlen = sizeof(struct sockaddr_un);
    int nonblock = options & PAL_OPTION_NONBLOCK ? SOCK_NONBLOCK : 0;

    ret = ocall_connect(AF_UNIX, SOCK_STREAM | nonblock, 0, /*ipv6_v6only=*/0,
                        (const struct sockaddr*)&addr, addrlen, NULL, NULL, &sock_options);
    if (ret < 0)
        return unix_to_pal_error(ret);

    PAL_HANDLE hdl = malloc(HANDLE_SIZE(pipe));
    if (!hdl) {
        ocall_close(ret);
        return -PAL_ERROR_NOMEM;
    }

    init_handle_hdr(HANDLE_HDR(hdl), PAL_TYPE_PIPE);
    HANDLE_HDR(hdl)->flags |= RFD(0) | WFD(0);
    hdl->pipe.fd            = ret;
    hdl->pipe.nonblocking   = (options & PAL_OPTION_NONBLOCK) ? PAL_TRUE : PAL_FALSE;

    /* padding with zeros is because the whole buffer is used in key derivation */
    memset(&hdl->pipe.name.str, 0, sizeof(hdl->pipe.name.str));
    memcpy(&hdl->pipe.name.str, name, strlen(name) + 1);

    /* create the SSL pre-shared key for this end of the pipe and initialize SSL context */
    ret = pipe_session_key(&hdl->pipe.name, &hdl->pipe.session_key);
    if (ret < 0) {
        ocall_close(hdl->pipe.fd);
        free(hdl);
        return -PAL_ERROR_DENIED;
    }

    hdl->pipe.ssl_ctx        = NULL;
    hdl->pipe.is_server      = true;
    hdl->pipe.handshake_done = 0;

    /* create a helper thread to initialize the SSL context (by performing SSL handshake);
     * we need a separate thread because the underlying handshake implementation is blocking
     * and assumes that client and server are two parallel entities (e.g., two threads) */
    PAL_HANDLE thread_hdl;
    ret = _DkThreadCreate(&thread_hdl, thread_handshake_func, /*param=*/hdl);
    if (ret < 0) {
        ocall_close(hdl->pipe.fd);
        free(hdl);
        return -PAL_ERROR_DENIED;
    }

    *handle = hdl;
    return 0;
}

/*!
 * \brief Create PAL handle with read and write ends of a pipe.
 *
 * This function creates a PAL handle of type `pipeprv` (anonymous pipe). In contrast to other types
 * of pipes, `pipeprv` encapsulates both ends of the pipe, backed by a host-level socketpair. This
 * type of pipe is typically reserved for internal LibOS usages, e.g. events (see `create_event()`).
 *
 * \param[out] handle  PAL handle of type `pipeprv` backed by a host-level socketpair.
 * \param[in]  options May contain PAL_OPTION_NONBLOCK.
 * \return             0 on success, negative PAL error code otherwise.
 */
static int pipe_private(PAL_HANDLE* handle, int options) {
    int fds[2];

    int nonblock = options & PAL_OPTION_NONBLOCK ? SOCK_NONBLOCK : 0;

    int ret = ocall_socketpair(AF_UNIX, SOCK_STREAM | nonblock, 0, fds);
    if (ret < 0)
        return unix_to_pal_error(ret);

    PAL_HANDLE hdl = malloc(HANDLE_SIZE(pipeprv));
    if (!hdl) {
        ocall_close(fds[0]);
        ocall_close(fds[1]);
        return -PAL_ERROR_NOMEM;
    }

    init_handle_hdr(HANDLE_HDR(hdl), PAL_TYPE_PIPEPRV);
    HANDLE_HDR(hdl)->flags  |= RFD(0) | WFD(1); /* first FD for reads, second FD for writes */
    hdl->pipeprv.fds[0]      = fds[0];
    hdl->pipeprv.fds[1]      = fds[1];
    hdl->pipeprv.nonblocking = (options & PAL_OPTION_NONBLOCK) ? PAL_TRUE : PAL_FALSE;

    /* pipeprv handle is currently used only for LibOS event emulation and does not send any real
     * messages (only dummy bytes to trigger events), so it doesn't need SSL context or key */

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
 *                                the name created by `get_graphene_unix_socket_addr`. Caller is
 *                                expected to call pipe_waitforclient() afterwards.
 *
 * - `type` is URI_TYPE_PIPE: create `pipe` handle (connecting socket) with the name created by
 *                            `get_graphene_unix_socket_addr`.
 *
 * \param[out] handle  Created PAL handle of type `pipeprv`, `pipesrv`, or `pipe`.
 * \param[in]  type    Can be URI_TYPE_PIPE or URI_TYPE_PIPE_SRV.
 * \param[in]  uri     Content is either NUL (for anonymous pipe) or a string with pipe name.
 * \param[in]  access  Not used.
 * \param[in]  share   Not used.
 * \param[in]  create  Not used.
 * \param[in]  options May contain PAL_OPTION_NONBLOCK.
 * \return             0 on success, negative PAL error code otherwise.
 */
static int pipe_open(PAL_HANDLE* handle, const char* type, const char* uri, int access, int share,
                     int create, int options) {
    if (access < 0 || access >= PAL_ACCESS_BOUND || !WITHIN_MASK(share, PAL_SHARE_MASK) ||
        !WITHIN_MASK(create, PAL_CREATE_MASK) || !WITHIN_MASK(options, PAL_OPTION_MASK))
        return -PAL_ERROR_INVAL;

    if (!strcmp(type, URI_TYPE_PIPE) && !*uri)
        return pipe_private(handle, options);

    if (strlen(uri) + 1 > PIPE_NAME_MAX)
        return -PAL_ERROR_INVAL;

    if (!strcmp(type, URI_TYPE_PIPE_SRV))
        return pipe_listen(handle, uri, options);

    if (!strcmp(type, URI_TYPE_PIPE))
        return pipe_connect(handle, uri, options);

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

    if (HANDLE_HDR(handle)->type != PAL_TYPE_PIPECLI && HANDLE_HDR(handle)->type != PAL_TYPE_PIPEPRV &&
        HANDLE_HDR(handle)->type != PAL_TYPE_PIPE)
        return -PAL_ERROR_NOTCONNECTION;

    ssize_t bytes;
    if (HANDLE_HDR(handle)->type == PAL_TYPE_PIPEPRV) {
        /* pipeprv are currently not encrypted, see pipe_private() */
        bytes = ocall_recv(handle->pipeprv.fds[0], buffer, len, NULL, NULL, NULL, NULL);
        if (bytes < 0)
            return unix_to_pal_error(bytes);
    } else {
        /* normal pipe, use a secure session (should be already initialized) */
        while (!__atomic_load_n(&handle->pipe.handshake_done, __ATOMIC_ACQUIRE))
            CPU_RELAX();

        if (!handle->pipe.ssl_ctx)
            return -PAL_ERROR_NOTCONNECTION;

        bytes = _DkStreamSecureRead(handle->pipe.ssl_ctx, buffer, len,
                                    /*is_blocking=*/!handle->pipe.nonblocking);
    }

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

    if (HANDLE_HDR(handle)->type != PAL_TYPE_PIPECLI && HANDLE_HDR(handle)->type != PAL_TYPE_PIPEPRV &&
        HANDLE_HDR(handle)->type != PAL_TYPE_PIPE)
        return -PAL_ERROR_NOTCONNECTION;

    ssize_t bytes;
    if (HANDLE_HDR(handle)->type == PAL_TYPE_PIPEPRV) {
        /* pipeprv are currently not encrypted, see pipe_private() */
        bytes = ocall_send(handle->pipeprv.fds[1], buffer, len, NULL, 0, NULL, 0);
        if (bytes < 0)
            return unix_to_pal_error(bytes);
    } else {
        /* normal pipe, use a secure session (should be already initialized) */
        while (!__atomic_load_n(&handle->pipe.handshake_done, __ATOMIC_ACQUIRE))
            CPU_RELAX();

        if (!handle->pipe.ssl_ctx)
            return -PAL_ERROR_NOTCONNECTION;

        bytes = _DkStreamSecureWrite(handle->pipe.ssl_ctx, buffer, len,
                                     /*is_blocking=*/!handle->pipe.nonblocking);
    }

    return bytes;
}

/*!
 * \brief Close pipe (both ends in case of `pipeprv`).
 *
 * \param[in] handle  PAL handle of type `pipeprv`, `pipesrv`, `pipecli`, or `pipe`.
 * \return            0 on success, negative PAL error code otherwise.
 */
static int pipe_close(PAL_HANDLE handle) {
    if (HANDLE_HDR(handle)->type == PAL_TYPE_PIPEPRV) {
        if (handle->pipeprv.fds[0] != PAL_IDX_POISON) {
            ocall_close(handle->pipeprv.fds[0]);
            handle->pipeprv.fds[0] = PAL_IDX_POISON;
        }
        if (handle->pipeprv.fds[1] != PAL_IDX_POISON) {
            ocall_close(handle->pipeprv.fds[1]);
            handle->pipeprv.fds[1] = PAL_IDX_POISON;
        }
    } else if (handle->pipe.fd != PAL_IDX_POISON) {
        while (!__atomic_load_n(&handle->pipe.handshake_done, __ATOMIC_ACQUIRE))
            CPU_RELAX();

        if (handle->pipe.ssl_ctx) {
            _DkStreamSecureFree((LIB_SSL_CONTEXT*)handle->pipe.ssl_ctx);
            handle->pipe.ssl_ctx = NULL;
        }
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

    if (HANDLE_HDR(handle)->type == PAL_TYPE_PIPEPRV) {
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
        /* This pipe might use a secure session, make sure all initial work is done. */
        while (!__atomic_load_n(&handle->pipe.handshake_done, __ATOMIC_ACQUIRE)) {
            CPU_RELAX();
        }

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
    attr->nonblocking  = HANDLE_HDR(handle)->type == PAL_TYPE_PIPEPRV ? handle->pipeprv.nonblocking
                                                                      : handle->pipe.nonblocking;
    attr->disconnected = HANDLE_HDR(handle)->flags & ERROR(0);

    /* get number of bytes available for reading (doesn't make sense for "listening" pipes) */
    attr->pending_size = 0;
    if (HANDLE_HDR(handle)->type != PAL_TYPE_PIPESRV) {
        ret = ocall_fionread(handle->pipe.fd);
        if (ret < 0)
            return unix_to_pal_error(ret);

        attr->pending_size = ret;
    }

    /* query if there is data available for reading/writing */
    if (HANDLE_HDR(handle)->type == PAL_TYPE_PIPEPRV) {
        /* for private pipe, readable and writable are queried on different fds */
        struct pollfd pfd[2] = {{.fd = handle->pipeprv.fds[0], .events = POLLIN,  .revents = 0},
                                {.fd = handle->pipeprv.fds[1], .events = POLLOUT, .revents = 0}};
        ret = ocall_poll(&pfd[0], 2, 0);
        if (ret < 0)
            return unix_to_pal_error(ret);

        attr->readable = ret >= 1 && (pfd[0].revents & (POLLIN | POLLERR | POLLHUP)) == POLLIN;
        attr->writable = ret >= 1 && (pfd[1].revents & (POLLOUT | POLLERR | POLLHUP)) == POLLOUT;
    } else {
        /* This pipe might use a secure session, make sure all initial work is done. */
        while (!__atomic_load_n(&handle->pipe.handshake_done, __ATOMIC_ACQUIRE)) {
            CPU_RELAX();
        }

        /* for non-private pipes, both readable and writable are queried on the same fd */
        short pfd_events = POLLIN;
        if (HANDLE_HDR(handle)->type != PAL_TYPE_PIPESRV) {
            /* querying for writing doesn't make sense for "listening" pipes */
            pfd_events |= POLLOUT;
        }

        struct pollfd pfd = {.fd = handle->pipe.fd, .events = pfd_events, .revents = 0};
        ret = ocall_poll(&pfd, 1, 0);
        if (ret < 0)
            return unix_to_pal_error(ret);

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

    if (HANDLE_HDR(handle)->type != PAL_TYPE_PIPEPRV) {
        /* This pipe might use a secure session, make sure all initial work is done. */
        while (!__atomic_load_n(&handle->pipe.handshake_done, __ATOMIC_ACQUIRE)) {
            CPU_RELAX();
        }
    }

    PAL_BOL* nonblocking = (HANDLE_HDR(handle)->type == PAL_TYPE_PIPEPRV)
                               ? &handle->pipeprv.nonblocking
                               : &handle->pipe.nonblocking;

    if (attr->nonblocking != *nonblocking) {
        int ret = ocall_fsetnonblock(handle->generic.fds[0], attr->nonblocking);
        if (ret < 0)
            return unix_to_pal_error(ret);

        *nonblocking = attr->nonblocking;
    }

    return 0;
}

/*!
 * \brief Retrieve full URI of PAL handle.
 *
 * Full URI is composed of the type and pipe name: "<type>:<pipename>".
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
        case PAL_TYPE_PIPESRV:
        case PAL_TYPE_PIPECLI:
            prefix_len = static_strlen(URI_TYPE_PIPE_SRV);
            prefix     = URI_TYPE_PIPE_SRV;
            break;
        case PAL_TYPE_PIPE:
            prefix_len = static_strlen(URI_TYPE_PIPE);
            prefix     = URI_TYPE_PIPE;
            break;
        case PAL_TYPE_PIPEPRV:
        default:
            return -PAL_ERROR_INVAL;
    }

    if (prefix_len >= count)
        return -PAL_ERROR_OVERFLOW;

    memcpy(buffer, prefix, prefix_len);
    buffer[prefix_len] = ':';
    buffer += prefix_len + 1;
    count -= prefix_len + 1;

    ret = snprintf(buffer, count, "%s\n", handle->pipe.name.str);
    if (buffer[ret - 1] != '\n') {
        memset(buffer, 0, count);
        return -PAL_ERROR_OVERFLOW;
    }

    buffer[ret - 1] = 0;
    buffer += ret - 1;
    count -= ret - 1;

    return old_count - count;
}

struct handle_ops g_pipe_ops = {
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

struct handle_ops g_pipeprv_ops = {
    .open           = &pipe_open,
    .read           = &pipe_read,
    .write          = &pipe_write,
    .close          = &pipe_close,
    .attrquerybyhdl = &pipe_attrquerybyhdl,
    .attrsetbyhdl   = &pipe_attrsetbyhdl,
};
