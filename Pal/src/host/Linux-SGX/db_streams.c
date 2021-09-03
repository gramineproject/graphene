/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs to open, read, write and get attribute of streams.
 */

#include <asm/fcntl.h>
#include <asm/poll.h>
#include <asm/socket.h>
#include <asm/stat.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/msg.h>
#include <linux/socket.h>
#include <linux/types.h>
#include <linux/wait.h>

#include "api.h"
#include "crypto.h"
#include "enclave_pages.h"
#include "enclave_pf.h"
#include "pal.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_linux_error.h"
#include "perm.h"
#include "stat.h"

#define DUMMYPAYLOAD     "dummypayload"
#define DUMMYPAYLOADSIZE (sizeof(DUMMYPAYLOAD))

static int g_log_fd = PAL_LOG_DEFAULT_FD;

struct hdl_header {
    uint8_t fds;       /* bitmask of host file descriptors corresponding to PAL handle */
    size_t  data_size; /* total size of serialized PAL handle */
};
static_assert((sizeof(((struct hdl_header*)0)->fds) * 8) >= MAX_FDS, "insufficient fds size");

static size_t addr_size(const struct sockaddr* addr) {
    switch (addr->sa_family) {
        case AF_INET:
            return sizeof(struct sockaddr_in);
        case AF_INET6:
            return sizeof(struct sockaddr_in6);
        default:
            return 0;
    }
}

bool stataccess(struct stat* stat, int acc) {
    unsigned int mode = stat->st_mode;

    if (g_linux_state.uid && g_linux_state.uid == stat->st_uid) {
        mode >>= 6;
        goto out;
    }

    if (g_linux_state.gid && g_linux_state.gid == stat->st_gid) {
        mode >>= 3;
        goto out;
    }

    if (!g_linux_state.uid)
        mode >>= 6;

out:
    return (mode & acc);
}

/* _DkStreamUnmap for internal use. Unmap stream at certain memory address.
   The memory is unmapped as a whole.*/
int _DkStreamUnmap(void* addr, uint64_t size) {
    int ret = flush_pf_maps(/*pf=*/NULL, addr, /*remove=*/true);
    if (ret < 0)
        return ret;

    return free_enclave_pages(addr, size);
}

static ssize_t handle_serialize(PAL_HANDLE handle, void** data) {
    int ret;
    const void* d1;
    const void* d2;
    size_t dsz1 = 0;
    size_t dsz2 = 0;
    bool free_d1 = false;
    bool free_d2 = false;

    /* find fields to serialize (depends on the handle type) and assign them to d1/d2; note that
     * no handle type has more than two such fields, and some have none at all */
    switch (PAL_GET_TYPE(handle)) {
        case PAL_TYPE_FILE:
            d1   = handle->file.realpath;
            dsz1 = strlen(handle->file.realpath) + 1;
            break;
        case PAL_TYPE_PIPE:
        case PAL_TYPE_PIPECLI:
            /* session key is part of handle but need to serialize SSL context */
            if (handle->pipe.ssl_ctx) {
                free_d1 = true;
                ret = _DkStreamSecureSave(handle->pipe.ssl_ctx, (const uint8_t**)&d1, &dsz1);
                if (ret < 0)
                    return -PAL_ERROR_DENIED;
            }
            break;
        case PAL_TYPE_PIPESRV:
        case PAL_TYPE_PIPEPRV:
            break;
        case PAL_TYPE_DEV:
            /* devices have no fields to serialize */
            break;
        case PAL_TYPE_DIR:
            if (handle->dir.realpath) {
                d1   = handle->dir.realpath;
                dsz1 = strlen(handle->dir.realpath) + 1;
            }
            break;
        case PAL_TYPE_TCP:
        case PAL_TYPE_TCPSRV:
        case PAL_TYPE_UDP:
        case PAL_TYPE_UDPSRV:
            if (handle->sock.bind) {
                d1   = (const void*)handle->sock.bind;
                dsz1 = addr_size(handle->sock.bind);
            }
            if (handle->sock.conn) {
                d2   = (const void*)handle->sock.conn;
                dsz2 = addr_size(handle->sock.conn);
            }
            break;
        case PAL_TYPE_PROCESS:
            /* session key is part of handle but need to serialize SSL context */
            if (handle->process.ssl_ctx) {
                free_d1 = true;
                ret = _DkStreamSecureSave(handle->process.ssl_ctx, (const uint8_t**)&d1, &dsz1);
                if (ret < 0)
                    return -PAL_ERROR_DENIED;
            }
            break;
        case PAL_TYPE_EVENTFD:
            break;
        default:
            return -PAL_ERROR_INVAL;
    }

    size_t hdlsz = handle_size(handle);
    void* buffer = malloc(hdlsz + dsz1 + dsz2);
    if (!buffer) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    /* copy into buffer all handle fields and then serialized fields */
    memcpy(buffer, handle, hdlsz);
    if (dsz1)
        memcpy(buffer + hdlsz, d1, dsz1);
    if (dsz2)
        memcpy(buffer + hdlsz + dsz1, d2, dsz2);
out:
    if (free_d1)
        free((void*)d1);
    if (free_d2)
        free((void*)d2);
    if (ret < 0)
        return ret;

    *data = buffer;
    return hdlsz + dsz1 + dsz2;
}

static int handle_deserialize(PAL_HANDLE* handle, const void* data, size_t size, int* fds) {
    int ret;

    PAL_HANDLE hdl = malloc(size);
    if (!hdl)
        return -PAL_ERROR_NOMEM;

    memcpy(hdl, data, size);
    size_t hdlsz = handle_size(hdl);

    /* update handle fields to point to correct contents (located right after handle itself) */
    switch (PAL_GET_TYPE(hdl)) {
        case PAL_TYPE_FILE:
            hdl->file.realpath = hdl->file.realpath ? (PAL_STR)hdl + hdlsz : NULL;
            hdl->file.chunk_hashes = (PAL_PTR)NULL;
            break;
        case PAL_TYPE_PIPE:
        case PAL_TYPE_PIPECLI:
            /* session key is part of handle but need to deserialize SSL context */
            hdl->pipe.fd = fds[0]; /* correct host FD must be passed to SSL context */
            ret = _DkStreamSecureInit(hdl, hdl->pipe.is_server, &hdl->pipe.session_key,
                                      (LIB_SSL_CONTEXT**)&hdl->pipe.ssl_ctx,
                                      (const uint8_t*)hdl + hdlsz, size - hdlsz);
            if (ret < 0) {
                free(hdl);
                return -PAL_ERROR_DENIED;
            }
            break;
        case PAL_TYPE_PIPESRV:
        case PAL_TYPE_PIPEPRV:
            break;
        case PAL_TYPE_DEV:
            break;
        case PAL_TYPE_DIR:
            hdl->dir.realpath = hdl->dir.realpath ? (PAL_STR)hdl + hdlsz : NULL;
            break;
        case PAL_TYPE_TCP:
        case PAL_TYPE_TCPSRV:
        case PAL_TYPE_UDP:
        case PAL_TYPE_UDPSRV: {
            size_t s1 = hdl->sock.bind ? addr_size((PAL_PTR)hdl + hdlsz) : 0;
            size_t s2 = hdl->sock.conn ? addr_size((PAL_PTR)hdl + hdlsz + s1) : 0;
            if (s1)
                hdl->sock.bind = (PAL_PTR)hdl + hdlsz;
            if (s2)
                hdl->sock.conn = (PAL_PTR)hdl + hdlsz + s2;
            break;
        }
        case PAL_TYPE_PROCESS:
            /* session key is part of handle but need to deserialize SSL context */
            hdl->process.stream = fds[0]; /* correct host FD must be passed to SSL context */
            ret = _DkStreamSecureInit(hdl, hdl->process.is_server, &hdl->process.session_key,
                                      (LIB_SSL_CONTEXT**)&hdl->process.ssl_ctx,
                                      (const uint8_t*)hdl + hdlsz, size - hdlsz);
            if (ret < 0) {
                free(hdl);
                return -PAL_ERROR_DENIED;
            }
            break;
        case PAL_TYPE_EVENTFD:
            break;
        default:
            free(hdl);
            return -PAL_ERROR_BADHANDLE;
    }

    *handle = hdl;
    return 0;
}

/*!
 * \brief Send `cargo` handle to a process identified via `hdl` handle.
 *
 * If `hdl` has an SSL context (i.e., its stream is encrypted), then `cargo` is sent encrypted.
 *
 * \param[in] hdl    Process stream on which to send `cargo`.
 * \param[in] cargo  Arbitrary handle to serialize and send on `hdl`.
 * \return           0 on success, negative PAL error code otherwise.
 */
int _DkSendHandle(PAL_HANDLE hdl, PAL_HANDLE cargo) {
    if (HANDLE_HDR(hdl)->type != PAL_TYPE_PROCESS)
        return -PAL_ERROR_BADHANDLE;

    /* serialize cargo handle into a blob hdl_data */
    void* hdl_data = NULL;
    ssize_t hdl_data_size = handle_serialize(cargo, &hdl_data);
    if (hdl_data_size < 0)
        return hdl_data_size;

    ssize_t ret;
    struct hdl_header hdl_hdr = {.fds = 0, .data_size = hdl_data_size};
    int fd = hdl->process.stream;

    /* apply bitmask of FDs-to-transfer to hdl_hdr.fds and populate `fds` with these FDs */
    int fds[MAX_FDS];
    int nfds = 0;
    for (int i = 0; i < MAX_FDS; i++)
        if (HANDLE_HDR(cargo)->flags & (RFD(i) | WFD(i))) {
            hdl_hdr.fds |= 1U << i;
            fds[nfds++] = cargo->generic.fds[i];
        }

    /* first send hdl_hdr so the recipient knows how many FDs were transferred + how large is cargo */
    ret = ocall_send(fd, &hdl_hdr, sizeof(struct hdl_header), NULL, 0, NULL, 0);
    if (ret < 0) {
        free(hdl_data);
        return unix_to_pal_error(ret);
    }

    /* construct ancillary data of FDs-to-transfer in a control message */
    size_t fds_size = nfds * sizeof(int);
    char control_buf[sizeof(struct cmsghdr) + fds_size];

    struct cmsghdr* control_hdr = (struct cmsghdr*)control_buf;
    control_hdr->cmsg_level     = SOL_SOCKET;
    control_hdr->cmsg_type      = SCM_RIGHTS;
    control_hdr->cmsg_len       = CMSG_LEN(fds_size);
    memcpy(CMSG_DATA(control_hdr), fds, fds_size);

    /* next send FDs-to-transfer as ancillary data */
    ret = ocall_send(fd, DUMMYPAYLOAD, DUMMYPAYLOADSIZE, NULL, 0, control_hdr,
                     control_hdr->cmsg_len);
    if (ret < 0) {
        free(hdl_data);
        return unix_to_pal_error(ret);
    }

    /* finally send the serialized cargo as payload (possibly encrypted) */
    if (hdl->process.ssl_ctx) {
        ret = _DkStreamSecureWrite(hdl->process.ssl_ctx, (uint8_t*)hdl_data, hdl_hdr.data_size,
                                   /*is_blocking=*/!hdl->process.nonblocking);
    } else {
        ret = ocall_write(fd, hdl_data, hdl_hdr.data_size);
        ret = ret < 0 ? unix_to_pal_error(ret) : ret;
    }

    free(hdl_data);
    return ret < 0 ? ret : 0;
}

/*!
 * \brief Receive `cargo` handle from a process identified via `hdl` handle.
 *
 * If `hdl` has an SSL context (i.e., its stream is encrypted), then `cargo` is sent encrypted.
 *
 * \param[in] hdl    Process stream on which to receive `cargo`.
 * \param[in] cargo  Arbitrary handle to receive on `hdl` and deserialize.
 * \return           0 on success, negative PAL error code otherwise.
 */
int _DkReceiveHandle(PAL_HANDLE hdl, PAL_HANDLE* cargo) {
    if (HANDLE_HDR(hdl)->type != PAL_TYPE_PROCESS)
        return -PAL_ERROR_BADHANDLE;

    ssize_t ret;
    struct hdl_header hdl_hdr;
    int fd = hdl->process.stream;

    /* first receive hdl_hdr so that we know how many FDs were transferred + how large is cargo */
    ret = ocall_recv(fd, &hdl_hdr, sizeof(hdl_hdr), NULL, NULL, NULL, NULL);
    if (ret < 0)
        return unix_to_pal_error(ret);

    if ((size_t)ret != sizeof(hdl_hdr)) {
        /* This check is to shield from a Iago attack. We know that ocall_send() in _DkSendHandle()
         * transfers the message atomically, and that our ocall_recv() receives it atomically. So
         * the only valid values for ret must be zero or the size of the header. */
        if (!ret)
            return -PAL_ERROR_TRYAGAIN;
        return -PAL_ERROR_DENIED;
    }

    /* prepare control-message buffer to receive ancillary data of FDs-to-transfer */
    int nfds = 0;
    for (int i = 0; i < MAX_FDS; i++)
        if (hdl_hdr.fds & (1U << i))
            nfds++;

    size_t control_buf_size = sizeof(struct cmsghdr) + nfds * sizeof(int);
    char control_buf[control_buf_size];

    /* next receive FDs-to-transfer as ancillary data */
    char dummypayload[DUMMYPAYLOADSIZE];
    ret = ocall_recv(fd, dummypayload, DUMMYPAYLOADSIZE, NULL, NULL, control_buf,
                     &control_buf_size);
    if (ret < 0)
        return unix_to_pal_error(ret);

    /* finally receive the serialized cargo as payload (possibly encrypted) */
    char hdl_data[hdl_hdr.data_size];

    if (hdl->process.ssl_ctx) {
        ret = _DkStreamSecureRead(hdl->process.ssl_ctx, (uint8_t*)hdl_data, hdl_hdr.data_size,
                                  /*is_blocking=*/!hdl->process.nonblocking);
    } else {
        ret = ocall_read(fd, hdl_data, hdl_hdr.data_size);
        ret = ret < 0 ? unix_to_pal_error(ret) : ret;
    }
    if (ret < 0)
        return ret;

    /* prepare array of FDs from the received FDs-to-transfer */
    struct cmsghdr* control_hdr = (struct cmsghdr*)control_buf;
    if (!control_hdr || control_hdr->cmsg_type != SCM_RIGHTS)
        return -PAL_ERROR_DENIED;

    int* fds = (int*)CMSG_DATA(control_hdr);

    /* deserialize cargo handle from a blob hdl_data */
    PAL_HANDLE handle = NULL;
    ret = handle_deserialize(&handle, hdl_data, hdl_hdr.data_size, fds);
    if (ret < 0)
        return ret;

    /* restore cargo handle's FDs from the received FDs-to-transfer */
    int fds_idx = 0;
    for (int i = 0; i < MAX_FDS; i++) {
        if (hdl_hdr.fds & (1U << i)) {
            if (fds_idx < nfds) {
                handle->generic.fds[i] = fds[fds_idx++];
            } else {
                HANDLE_HDR(handle)->flags &= ~(RFD(i) | WFD(i));
            }
        }
    }

    *cargo = handle;
    return 0;
}

int _DkInitDebugStream(const char* path) {
    int ret;

    if (g_log_fd != PAL_LOG_DEFAULT_FD) {
        ret = ocall_close(g_log_fd);
        g_log_fd = PAL_LOG_DEFAULT_FD;
        if (ret < 0)
            return unix_to_pal_error(ret);
    }

    ret = ocall_open(path, O_WRONLY | O_APPEND | O_CREAT, PERM_rw_______);
    if (ret < 0)
        return unix_to_pal_error(ret);
    g_log_fd = ret;
    return 0;
}

int _DkDebugLog(const void* buf, size_t size) {
    if (g_log_fd < 0)
        return -PAL_ERROR_BADHANDLE;

    // TODO: add retrying on EINTR
    ssize_t ret = ocall_write(g_log_fd, buf, size);
    if (ret < 0 || (size_t)ret != size) {
        return ret < 0 ? unix_to_pal_error(ret) : -PAL_ERROR_INTERRUPTED;
    }
    return 0;
}
