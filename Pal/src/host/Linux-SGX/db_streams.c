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

#include <linux/types.h>

#include "api.h"
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
#include <linux/wait.h>

#include "enclave_pages.h"

void _DkPrintConsole(const void* buf, int size) {
    ocall_write(2 /*stderr*/, buf, size);
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

/* _DkStreamUnmap for internal use. Unmap stream at certain memory address.
   The memory is unmapped as a whole.*/
int _DkStreamUnmap(void* addr, uint64_t size) {
    int ret = flush_pf_maps(/*pf=*/NULL, addr, /*remove=*/true);
    if (ret < 0)
        return ret;
    /* Just let the kernel tell us if the mapping isn't good. */
    free_pages(addr, size);
    return 0;
}

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

int handle_serialize(PAL_HANDLE handle, void** data) {
    int hdlsz = handle_size(handle);
    const void* d1;
    const void* d2;
    int dsz1 = 0, dsz2 = 0;

    // ~ Check cargo PAL_HANDLE - is allowed to be sent (White List checking
    // of cargo type)
    // ~ Also, Initialize common parameter formessage passing
    // Channel between parent and child
    switch (PAL_GET_TYPE(handle)) {
        case pal_type_file:
            d1   = handle->file.realpath;
            dsz1 = strlen(handle->file.realpath) + 1;
            break;
        case pal_type_pipe:
        case pal_type_pipesrv:
        case pal_type_pipecli:
        case pal_type_pipeprv:
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

    void* buffer = malloc(hdlsz + dsz1 + dsz2);
    if (!buffer)
        return -PAL_ERROR_NOMEM;

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

#ifndef SEEK_SET
#define SEEK_SET 0
#endif

int handle_deserialize(PAL_HANDLE* handle, const void* data, int size) {
    PAL_HANDLE hdl_data = (void*)data, hdl = NULL;
    int hdlsz = handle_size(hdl_data), ret = -PAL_ERROR_NOMEM;

    data += hdlsz;
    size -= hdlsz;

    // recreate PAL_HANDLE based on type
    switch (PAL_GET_TYPE(hdl_data)) {
        case pal_type_file: {
            int l = strlen((const char*)data) + 1;
            hdl   = malloc(hdlsz + l);
            if (!hdl)
                break;
            memcpy(hdl, hdl_data, hdlsz);
            memcpy((void*)hdl + hdlsz, data, l);
            hdl->file.realpath = (PAL_STR)hdl + hdlsz;
            hdl->file.stubs    = (PAL_PTR)NULL;
            break;
        }
        case pal_type_pipe:
        case pal_type_pipesrv:
        case pal_type_pipecli:
        case pal_type_pipeprv:
            hdl = malloc_copy(hdl_data, hdlsz);
            break;
        case pal_type_dev: {
            int l = hdl_data->dev.realpath ? strlen((const char*)data) + 1 : 0;
            hdl   = malloc(hdlsz + l);
            if (!hdl)
                break;
            memcpy(hdl, hdl_data, hdlsz);
            if (l) {
                memcpy((void*)hdl + hdlsz, data, l);
                hdl->dev.realpath = (void*)hdl + hdlsz;
            }
            break;
        }
        case pal_type_dir: {
            int l = hdl_data->dir.realpath ? strlen((const char*)data) + 1 : 0;
            hdl   = malloc(hdlsz + l);
            if (!hdl)
                break;
            memcpy(hdl, hdl_data, hdlsz);
            if (l) {
                memcpy((void*)hdl + hdlsz, data, l);
                hdl->dir.realpath = (void*)hdl + hdlsz;
            }
            break;
        }
        case pal_type_tcp:
        case pal_type_tcpsrv:
        case pal_type_udp:
        case pal_type_udpsrv: {
            int s1 = 0, s2 = 0;
            if (hdl_data->sock.bind)
                s1 = addr_size(data);
            if (hdl_data->sock.conn)
                s2 = addr_size(data + s1);
            hdl = malloc(hdlsz + s1 + s2);
            if (!hdl)
                break;
            memcpy(hdl, hdl_data, hdlsz);
            if (s1) {
                memcpy((void*)hdl + hdlsz, data, s1);
                hdl->sock.bind = (PAL_PTR)hdl + hdlsz;
            }
            if (s2) {
                memcpy((void*)hdl + hdlsz + s1, data + s1, s2);
                hdl->sock.conn = (PAL_PTR)hdl + hdlsz + s2;
            }
            break;
        }
        case pal_type_process:
        case pal_type_eventfd:
            hdl = malloc_copy(hdl_data, hdlsz);
            break;
        default:
            return -PAL_ERROR_BADHANDLE;
    }

    if (!hdl)
        return ret;

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

// Header for DkSendHandle and DkRecvHandle
struct hdl_header {
    unsigned short fds : (MAX_FDS);
    unsigned short data_size : (16 - (MAX_FDS));
};

/* _DkSendHandle for internal use. Send a Pal Handle over the given
   process handle. Return 1 if success else return negative error code */
int _DkSendHandle(PAL_HANDLE hdl, PAL_HANDLE cargo) {
    struct hdl_header hdl_hdr;
    void* hdl_data;
    int ret = handle_serialize(cargo, &hdl_data);
    if (ret < 0)
        return ret;

    hdl_hdr.fds       = 0;
    hdl_hdr.data_size = ret;
    unsigned int fds[MAX_FDS];
    unsigned int nfds = 0;
    for (int i = 0; i < MAX_FDS; i++)
        if (HANDLE_HDR(cargo)->flags & (RFD(i) | WFD(i))) {
            hdl_hdr.fds |= 1U << i;
            fds[nfds++] = cargo->generic.fds[i];
        }

    int ch = hdl->process.cargo;
    ret    = ocall_send(ch, &hdl_hdr, sizeof(struct hdl_header), NULL, 0, NULL, 0);

    if (IS_ERR(ret)) {
        free(hdl_data);
        return unix_to_pal_error(ERRNO(ret));
    }

    uint64_t fds_size = nfds * sizeof(unsigned int);
    char cbuf[sizeof(struct cmsghdr) + fds_size];

    struct cmsghdr* chdr = (struct cmsghdr*)cbuf;
    chdr->cmsg_level = SOL_SOCKET;
    chdr->cmsg_type = SCM_RIGHTS;
    chdr->cmsg_len = CMSG_LEN(fds_size);
    memcpy(CMSG_DATA(chdr), fds, fds_size);

    ret = ocall_send(ch, hdl_data, hdl_hdr.data_size, NULL, 0, chdr, chdr->cmsg_len);

    free(hdl_data);
    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : 0;
}

/* _DkRecvHandle for internal use. Receive and return a PAL_HANDLE over the
   given PAL_HANDLE else return negative value. */
int _DkReceiveHandle(PAL_HANDLE hdl, PAL_HANDLE* cargo) {
    struct hdl_header hdl_hdr;

    if (!IS_HANDLE_TYPE(hdl, process))
        return -PAL_ERROR_BADHANDLE;

    int ch = hdl->process.cargo;

    int ret = ocall_recv(ch, &hdl_hdr, sizeof(struct hdl_header), NULL, NULL, NULL, NULL);

    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    if ((size_t)ret < sizeof(struct hdl_header)) {
        /*
         * This code block is just in case to cover all the possibilities
         * to shield Iago attack.
         * We know that the file descriptor is an unix domain socket with
         * blocking mode and that the sender, _DkSendHandle() above, sends the
         * header with single sendmsg syscall by ocall_send() which
         * transfers a message atomically.
         *
         * read size == 0: return error for the caller to try again.
         *                 It should result in EINTR.
         *
         * read size > 0: return error for the caller to give up this file
         *                descriptor.
         *                If the header can't be send atomically for some
         *                reason, the sender should get EMSGSIZE.
         */
        if (!ret)
            return -PAL_ERROR_TRYAGAIN;
        return -PAL_ERROR_DENIED;
    }

    uint32_t nfds = 0;
    for (int i = 0; i < MAX_FDS; i++)
        if (hdl_hdr.fds & (1U << i))
            nfds++;

    uint64_t fds_size  = nfds * sizeof(unsigned int);
    uint64_t cbuf_size = sizeof(struct cmsghdr) + fds_size;

    char buffer[hdl_hdr.data_size];
    char cbuf[cbuf_size];
    ret = ocall_recv(ch, buffer, hdl_hdr.data_size, NULL, NULL, cbuf, &cbuf_size);

    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    nfds = 0;
    uint32_t fds[fds_size];
    struct cmsghdr* chdr = (struct cmsghdr*)cbuf;
    if (chdr->cmsg_type == SCM_RIGHTS) {
        nfds = (chdr->cmsg_len - sizeof(struct cmsghdr)) / sizeof(int);
        memcpy(fds, CMSG_DATA(chdr), nfds * sizeof(int));
    }

    PAL_HANDLE handle = NULL;
    ret               = handle_deserialize(&handle, buffer, hdl_hdr.data_size);
    if (ret < 0)
        return ret;

    uint32_t n = 0;
    for (uint32_t i = 0; i < MAX_FDS; i++)
        if (hdl_hdr.fds & (1U << i)) {
            if (n < nfds) {
                handle->generic.fds[i] = fds[n++];
            } else {
                HANDLE_HDR(handle)->flags &= ~(RFD(i) | WFD(i));
            }
        }

    *cargo = handle;
    return 0;
}
