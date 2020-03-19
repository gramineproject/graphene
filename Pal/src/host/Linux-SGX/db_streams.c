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
 * db_stream.c
 *
 * This file contains APIs to open, read, write and get attribute of
 * streams.
 */

#include "api.h"
#include "enclave_pages.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_linux_error.h"

typedef __kernel_pid_t pid_t;
#include <asm/fcntl.h>
#include <asm/poll.h>
#include <asm/socket.h>
#include <asm/stat.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/msg.h>
#include <linux/socket.h>
#include <linux/stat.h>
#include <linux/types.h>
#include <linux/wait.h>


struct hdl_header {
    unsigned short fds : (MAX_FDS);
    unsigned short data_size : (16 - (MAX_FDS));
};

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

    if (linux_state.uid && linux_state.uid == stat->st_uid) {
        mode >>= 6;
        goto out;
    }

    if (linux_state.gid && linux_state.gid == stat->st_gid) {
        mode >>= 3;
        goto out;
    }

    if (!linux_state.uid)
        mode >>= 6;

out:
    return (mode & acc);
}

void _DkPrintConsole(const void* buf, int size) {
    ocall_write(2 /*stderr*/, buf, size);
}

/* _DkStreamUnmap for internal use. Unmap stream at certain memory address.
   The memory is unmapped as a whole.*/
int _DkStreamUnmap(void* addr, uint64_t size) {
    return free_enclave_pages(addr, size);
}

static ssize_t handle_serialize(PAL_HANDLE handle, void** data) {
    const void* d1;
    const void* d2;
    size_t dsz1 = 0;
    size_t dsz2 = 0;

    /* find fields to serialize (depends on the handle type) and assign them to d1/d2; note that
     * no handle type has more than two such fields, and some have none at all */
    switch (PAL_GET_TYPE(handle)) {
        case pal_type_file:
            d1   = handle->file.realpath;
            dsz1 = strlen(handle->file.realpath) + 1;
            break;
        case pal_type_pipe:
        case pal_type_pipesrv:
        case pal_type_pipecli:
        case pal_type_pipeprv:
            /* pipes have no fields to serialize */
            break;
        case pal_type_dev:
            if (handle->dev.realpath) {
                d1   = handle->dev.realpath;
                dsz1 = strlen(handle->dev.realpath) + 1;
            }
            break;
        case pal_type_dir:
            if (handle->dir.realpath) {
                d1   = handle->dir.realpath;
                dsz1 = strlen(handle->dir.realpath) + 1;
            }
            break;
        case pal_type_tcp:
        case pal_type_tcpsrv:
        case pal_type_udp:
        case pal_type_udpsrv:
            if (handle->sock.bind) {
                d1   = (const void*)handle->sock.bind;
                dsz1 = addr_size(handle->sock.bind);
            }
            if (handle->sock.conn) {
                d2   = (const void*)handle->sock.conn;
                dsz2 = addr_size(handle->sock.conn);
            }
            break;
        case pal_type_process:
        case pal_type_eventfd:
            break;
        default:
            return -PAL_ERROR_INVAL;
    }

    size_t hdlsz = handle_size(handle);
    void* buffer = malloc(hdlsz + dsz1 + dsz2);
    if (!buffer)
        return -PAL_ERROR_NOMEM;

    /* copy into buffer all handle fields and then serialized fields */
    memcpy(buffer, handle, hdlsz);
    if (dsz1)
        memcpy(buffer + hdlsz, d1, dsz1);
    if (dsz2)
        memcpy(buffer + hdlsz + dsz1, d2, dsz2);

    if (PAL_GET_TYPE(handle) == pal_type_process) {
        /* must not leak session key and SSL context -> zero them */
        memset(buffer + offsetof(struct pal_handle, process.session_key), 0, sizeof(handle->process.session_key));
        memset(buffer + offsetof(struct pal_handle, process.ssl_ctx), 0, sizeof(handle->process.ssl_ctx));
    }

    *data = buffer;
    return hdlsz + dsz1 + dsz2;
}

static int handle_deserialize(PAL_HANDLE* handle, const void* data, size_t size) {
    PAL_HANDLE hdl = malloc(size);
    if (!hdl)
        return -PAL_ERROR_NOMEM;

    memcpy(hdl, data, size);
    size_t hdlsz = handle_size(hdl);

    /* update corresponding handle fields to point to serialized fields */
    switch (PAL_GET_TYPE(hdl)) {
        case pal_type_file:
            hdl->file.realpath = hdl->file.realpath ? (PAL_STR)hdl + hdlsz : NULL;
            hdl->file.stubs    = (PAL_PTR)NULL;
            break;
        case pal_type_pipe:
        case pal_type_pipesrv:
        case pal_type_pipecli:
        case pal_type_pipeprv:
            break;
        case pal_type_dev:
            hdl->dev.realpath = hdl->dev.realpath ? (PAL_STR)hdl + hdlsz : NULL;
            break;
        case pal_type_dir:
            hdl->dir.realpath = hdl->dir.realpath ? (PAL_STR)hdl + hdlsz : NULL;
            break;
        case pal_type_tcp:
        case pal_type_tcpsrv:
        case pal_type_udp:
        case pal_type_udpsrv: {
            size_t s1 = hdl->sock.bind ? addr_size((PAL_PTR)hdl + hdlsz) : 0;
            size_t s2 = hdl->sock.conn ? addr_size((PAL_PTR)hdl + hdlsz + s1) : 0;
            if (s1)
                hdl->sock.bind = (PAL_PTR)hdl + hdlsz;
            if (s2)
                hdl->sock.conn = (PAL_PTR)hdl + hdlsz + s2;
            break;
        }
        case pal_type_process:
        case pal_type_eventfd:
            break;
        default:
            return -PAL_ERROR_BADHANDLE;
    }

    if (PAL_GET_TYPE(hdl) == pal_type_process) {
        /* must not have leaked session key and SSL context, verify */
        static PAL_SESSION_KEY zero_session_key;
        __UNUSED(zero_session_key); /* otherwise GCC with Release build complains */

        assert(memcmp(hdl->process.session_key, zero_session_key, sizeof(zero_session_key)) == 0);
        assert(hdl->process.ssl_ctx == 0);
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
    if (!IS_HANDLE_TYPE(hdl, process))
        return -PAL_ERROR_BADHANDLE;

    /* serialize cargo handle into a blob hdl_data */
    void* hdl_data = NULL;
    ssize_t hdl_data_size = handle_serialize(cargo, &hdl_data);
    if (hdl_data_size < 0)
        return hdl_data_size;

    ssize_t ret;
    struct hdl_header hdl_hdr = {.fds = 0, .data_size = hdl_data_size};
    int fd = hdl->process.cargo;

    /* apply bitmask of FDs-to-transfer to hdl_hdr.fds and populate `fds` with these FDs */
    int fds[MAX_FDS];
    int nfds = 0;
    for (int i = 0; i < MAX_FDS; i++)
        if (HANDLE_HDR(cargo)->flags & (RFD(i) | WFD(i))) {
            hdl_hdr.fds |= 1U << i;
            fds[nfds++] = cargo->generic.fds[i];
        }

    /* first send hdl_hdr so the recipient knows how many FDs were transfered + how large is cargo */
    ret = ocall_send(fd, &hdl_hdr, sizeof(struct hdl_header), NULL, 0, NULL, 0);
    if (IS_ERR(ret)) {
        free(hdl_data);
        return unix_to_pal_error(ERRNO(ret));
    }

    /* construct ancillary data of FDs-to-transfer in a control message */
    size_t fds_size = nfds * sizeof(int);
    char cbuf[sizeof(struct cmsghdr) + fds_size];

    struct cmsghdr* chdr = (struct cmsghdr*)cbuf;
    chdr->cmsg_level     = SOL_SOCKET;
    chdr->cmsg_type      = SCM_RIGHTS;
    chdr->cmsg_len       = CMSG_LEN(fds_size);
    memcpy(CMSG_DATA(chdr), fds, fds_size);

    /* finally send the serialized cargo as payload and FDs-to-transfer as ancillary data */
    ret = ocall_send(fd, hdl_data, hdl_hdr.data_size, NULL, 0, chdr, chdr->cmsg_len);
    if (IS_ERR(ret)) {
        free(hdl_data);
        return unix_to_pal_error(ERRNO(ret));
    }

    free(hdl_data);
    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : 0;
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
    if (!IS_HANDLE_TYPE(hdl, process))
        return -PAL_ERROR_BADHANDLE;

    ssize_t ret;
    struct hdl_header hdl_hdr;
    int fd = hdl->process.cargo;

    /* first receive hdl_hdr so that we know how many FDs were transfered + how large is cargo */
    ret = ocall_recv(fd, &hdl_hdr, sizeof(hdl_hdr), NULL, NULL, NULL, NULL);
    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    if ((size_t)ret < sizeof(hdl_hdr)) {
        /* This check is to shield from a Iago attack. We know that ocall_send() in _DkSendHandle()
         * transfers the message atomically, and that our ocall_recv() receives it atomically. So
         * the only valid values for ret must be 0 or the size of the header. */
        if (!ret)
            return -PAL_ERROR_TRYAGAIN;
        return -PAL_ERROR_DENIED;
    }

    /* prepare control-message buffer to receive ancillary data of FDs-to-transfer */
    int nfds = 0;
    for (int i = 0; i < MAX_FDS; i++)
        if (hdl_hdr.fds & (1U << i))
            nfds++;

    size_t fds_size  = nfds * sizeof(int);
    size_t cbuf_size = sizeof(struct cmsghdr) + fds_size;

    char hdl_data[hdl_hdr.data_size];
    char cbuf[cbuf_size];

    /* finally receive the serialized cargo as payload and FDs-to-transfer as ancillary data */
    ret = ocall_recv(fd, hdl_data, hdl_hdr.data_size, NULL, NULL, cbuf, &cbuf_size);
    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    struct cmsghdr* chdr = (struct cmsghdr*)cbuf;
    if (chdr->cmsg_type != SCM_RIGHTS)
        return -PAL_ERROR_DENIED;

    /* deserialize cargo handle from a blob hdl_data */
    PAL_HANDLE handle = NULL;
    ret = handle_deserialize(&handle, hdl_data, hdl_hdr.data_size);
    if (IS_ERR(ret))
        return ret;

    /* restore cargo handle's FDs from the received FDs-to-transfer */
    int fds[fds_size];
    nfds = (chdr->cmsg_len - sizeof(struct cmsghdr)) / sizeof(int);
    memcpy(fds, CMSG_DATA(chdr), nfds * sizeof(int));

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
