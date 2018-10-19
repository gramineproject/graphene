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
 * db_stream.c
 *
 * This file contains APIs to open, read, write and get attribute of
 * streams.
 */

#include "pal_defs.h"
#include "pal_linux_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_debug.h"
#include "pal_error.h"
#include "api.h"

#include <linux/types.h>
typedef __kernel_pid_t pid_t;
#include <linux/stat.h>
#include <linux/msg.h>
#include <linux/socket.h>
#include <linux/wait.h>
#include <asm/fcntl.h>
#include <asm/stat.h>
#include <asm/socket.h>
#include <asm/poll.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <asm/errno.h>

void _DkPrintConsole (const void * buf, int size)
{
    INLINE_SYSCALL(write, 3, 2, buf, size);
}

bool stataccess (struct stat * stat, int acc)
{
    mode_t mode = stat->st_mode;

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

int handle_set_cloexec (PAL_HANDLE handle, bool enable)
{
    for (int i = 0 ; i < MAX_FDS ; i++)
        if (HANDLE_HDR(handle)->flags & (RFD(i)|WFD(i))) {
            long flags = enable ? FD_CLOEXEC : 0;
            int ret = INLINE_SYSCALL(fcntl, 3,
                                     handle->generic.fds[i], F_SETFD,
                                     flags);
            if (IS_ERR(ret) && ERRNO(ret) != EBADF)
                return -PAL_ERROR_DENIED;
        }

    return 0;
}

/* _DkStreamUnmap for internal use. Unmap stream at certain memory address.
   The memory is unmapped as a whole.*/
int _DkStreamUnmap (void * addr, uint64_t size)
{
    /* Just let the kernel tell us if the mapping isn't good. */
    int ret = INLINE_SYSCALL(munmap, 2, addr, size);

    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    return 0;
}

#define addr_size(addr)                                     \
    ({  int _size = 0;                                      \
        switch (((struct sockaddr *) addr)->sa_family) {    \
            case AF_INET:                                   \
                _size = sizeof(struct sockaddr_in); break;  \
            case AF_INET6:                                  \
                _size = sizeof(struct sockaddr_in6); break; \
            default: break;                                 \
        } _size;                                            \
    })

int handle_serialize (PAL_HANDLE handle, void ** data)
{
    int hdlsz = handle_size(handle);
    const void * d1, * d2;
    int dsz1 = 0, dsz2 = 0;

    // ~ Check cargo PAL_HANDLE - is allowed to be sent (White List checking
    // of cargo type)
    // ~ Also, Initialize common parameter formessage passing
    // Channel between parent and child
    switch(PAL_GET_TYPE(handle)) {
        case pal_type_file:
            d1 = handle->file.realpath;
            dsz1 = strlen(handle->file.realpath) + 1;
            break;
        case pal_type_pipe:
        case pal_type_pipesrv:
        case pal_type_pipecli:
        case pal_type_pipeprv:
            break;
        case pal_type_dev:
            if (handle->dev.realpath) {
                d1 = handle->dev.realpath;
                dsz1 = strlen(handle->dev.realpath) + 1;
            }
            break;
        case pal_type_dir:
            if (handle->dir.realpath) {
                d1 = handle->dir.realpath;
                dsz1 = strlen(handle->dir.realpath) + 1;
            }
            break;
        case pal_type_tcp:
        case pal_type_tcpsrv:
        case pal_type_udp:
        case pal_type_udpsrv:
            if (handle->sock.bind) {
                d1 = (const void *) handle->sock.bind;
                dsz1 = addr_size(handle->sock.bind);
            }
            if (handle->sock.conn) {
                d2 = (const void *) handle->sock.conn;
                dsz2 = addr_size(handle->sock.conn);
            }
            break;
        case pal_type_gipc:
        case pal_type_process:
            break;
        default:
            return -PAL_ERROR_INVAL;
    }

    void * buffer = malloc(hdlsz + dsz1 + dsz2);
    if (!buffer)
        return -PAL_ERROR_NOMEM;

    memcpy(buffer, handle, hdlsz);
    if (dsz1)
        memcpy(buffer + hdlsz, d1, dsz1);
    if (dsz2)
        memcpy(buffer + hdlsz + dsz1, d2, dsz2);

    *data = buffer;
    return hdlsz + dsz1 + dsz2;
}

#ifndef SEEK_SET
# define SEEK_SET 0
#endif

int handle_deserialize (PAL_HANDLE * handle, const void * data, int size)
{
    PAL_HANDLE hdl_data = (void *) data, hdl = NULL;
    int hdlsz = handle_size(hdl_data), ret = -PAL_ERROR_NOMEM;

    data += hdlsz;
    size -= hdlsz;

    // recreate PAL_HANDLE based on type
    switch(PAL_GET_TYPE(hdl_data)) {
        case pal_type_file: {
            int l = strlen((const char *) data) + 1;
            hdl = malloc(hdlsz + l);
            if (!hdl)
                break;
            memcpy(hdl, hdl_data, hdlsz);
            memcpy((void *) hdl + hdlsz, data, l);
            hdl->file.realpath = (void *) hdl + hdlsz;
            break;
        }
        case pal_type_pipe:
        case pal_type_pipesrv:
        case pal_type_pipecli:
        case pal_type_pipeprv:
            hdl = malloc_copy(hdl_data, hdlsz);
            break;
        case pal_type_dev: {
            int l = hdl_data->dev.realpath ? strlen((const char *) data) + 1 : 0;
            hdl = malloc(hdlsz + l);
            if (!hdl)
                break;
            memcpy(hdl, hdl_data, hdlsz);
            if (l) {
                memcpy((void *) hdl + hdlsz, data, l);
                hdl->dev.realpath = (void *) hdl + hdlsz;
            }
            break;
        }
        case pal_type_dir: {
            int l = hdl_data->dir.realpath ? strlen((const char *) data) + 1 : 0;
            hdl = malloc(hdlsz + l);
            if (!hdl)
                break;
            memcpy(hdl, hdl_data, hdlsz);
            if (l) {
                memcpy((void *) hdl + hdlsz, data, l);
                hdl->dir.realpath = (void *) hdl + hdlsz;
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
                memcpy((void *) hdl + hdlsz, data, s1);
                hdl->sock.bind = (PAL_PTR) hdl + hdlsz;
            }
            if (s2) {
                memcpy((void *) hdl + hdlsz + s1, data + s1, s2);
                hdl->sock.conn = (PAL_PTR) hdl + hdlsz + s2;
            }
            break;
        }
        case pal_type_gipc:
        case pal_type_process:
            hdl = malloc_copy(hdl_data, hdlsz);
            break;
        default :
            return -PAL_ERROR_BADHANDLE;
    }

    if (!hdl)
        return ret;

    *handle = hdl;
    return 0;
}

// Header for DkSendHandle and DkRecvHandle
struct hdl_header {
    unsigned short fds:(MAX_FDS);
    unsigned short data_size:(16-(MAX_FDS));
};

/* _DkSendHandle for internal use. Send a Pal Handle over the given
   process handle. Return 1 if success else return negative error code */
int _DkSendHandle (PAL_HANDLE hdl, PAL_HANDLE cargo)
{
    struct hdl_header hdl_hdr;
    void * hdl_data;
    int ret = handle_serialize(cargo, &hdl_data);
    if (ret < 0)
        return ret;

    hdl_hdr.fds = 0;
    hdl_hdr.data_size = ret;
    int fds[MAX_FDS];
    int nfds = 0;
    for (int i = 0 ; i < MAX_FDS ; i++)
        if (HANDLE_HDR(cargo)->flags & (RFD(i)|WFD(1))) {
            hdl_hdr.fds |= 1U << i;
            fds[nfds++] = cargo->generic.fds[i];
        }

    // ~ Initialize common parameter formessage passing
    // Channel between parent and child
    int ch = hdl->process.cargo;

    // Declare variables required for sending the message
    struct msghdr hdr; // message header
    struct cmsghdr * chdr; //control message header
    struct iovec iov[1]; // IO Vector

    iov[0].iov_base = &hdl_hdr;
    iov[0].iov_len = sizeof(struct hdl_header);
    hdr.msg_name = NULL;
    hdr.msg_namelen = 0;
    hdr.msg_iov = iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = NULL;
    hdr.msg_controllen = 0;
    hdr.msg_flags = 0;

    ret = INLINE_SYSCALL(sendmsg, 3, ch, &hdr, MSG_NOSIGNAL);

    // Unlock is error
    if (IS_ERR(ret)) {
        free(hdl_data);
        return -PAL_ERROR_DENIED;
    }

    /* Message Body Composition:
       IOVEC[0]: PAL_HANDLE
       IOVEC[1..n]: Additional handle member follow
       Control Message: file descriptors */

    // Control message buffer with added space for 2 fds (ie. max size
    // that it will have)
    char cbuf[sizeof(struct cmsghdr) + nfds * sizeof(int)];

    // Initialize iovec[0] with struct PAL_HANDLE
    iov[0].iov_base = hdl_data;
    iov[0].iov_len = hdl_hdr.data_size;

    hdr.msg_iov = iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = cbuf; // Control Message Buffer
    hdr.msg_controllen = sizeof(struct cmsghdr) + sizeof(int) * nfds;

    // Fill control message infomation for the file descriptors
    // Check hdr.msg_controllen >= sizeof(struct cmsghdr) to point to
    // cbuf, which is redundant based on the above code as we have
    // statically allocated memory.
    // or (struct cmsghdr*) cbuf
    chdr = CMSG_FIRSTHDR(&hdr); // Pointer to msg_control
    chdr->cmsg_level = SOL_SOCKET; // Originating Protocol
    chdr->cmsg_type = SCM_RIGHTS; // Protocol Specific Type
    // Length of control message = sizeof(struct cmsghdr) + nfds
    chdr->cmsg_len = CMSG_LEN(sizeof(int) * nfds);

    // Copy the fds below control header
    memcpy(CMSG_DATA(chdr), fds, sizeof(int) * nfds);

    // Also, Update main header with control message length (duplicate)
    hdr.msg_controllen = chdr->cmsg_len;

    //  Send message
    ret = INLINE_SYSCALL(sendmsg, 3, ch, &hdr, 0);

    free(hdl_data);
    return IS_ERR(ret) ? -PAL_ERROR_DENIED : 0;
}

/* _DkRecvHandle for internal use. Receive and return a PAL_HANDLE over the
   given PAL_HANDLE else return negative value. */
int _DkReceiveHandle(PAL_HANDLE hdl, PAL_HANDLE * cargo)
{
    struct hdl_header hdl_hdr;

    // ~ Check connection PAL_HANDLE - is of process type for sending handle
    // else fail
    if (!IS_HANDLE_TYPE(hdl, process))
        return -PAL_ERROR_BADHANDLE;

    // ~ Initialize common parameter for message passing
    // Channel between parent and child
    int ch = hdl->process.cargo;

    struct msghdr hdr;
    struct iovec iov[1];

    iov[0].iov_base = &hdl_hdr;
    iov[0].iov_len = sizeof(struct hdl_header);
    hdr.msg_name = NULL;
    hdr.msg_namelen = 0;
    hdr.msg_iov = iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = NULL;
    hdr.msg_controllen = 0;
    hdr.msg_flags = 0;

    int ret = INLINE_SYSCALL(recvmsg, 3, ch, &hdr, 0);

    if (IS_ERR(ret) || ret < sizeof(struct hdl_header)) {
        if (!IS_ERR(ret))
            return -PAL_ERROR_TRYAGAIN;

        if (ERRNO(ret) != EINTR && ERRNO(ret) != ERESTART)
            return -ERRNO(ret);
    }

    // initialize variables to get body
    void * buffer = __alloca(hdl_hdr.data_size);
    int nfds = 0;

    for (int i = 0 ; i < MAX_FDS ; i++)
        if (hdl_hdr.fds & (1U << i))
            nfds++;

    // receive PAL_HANDLE contents in the body
    char cbuf[sizeof(struct cmsghdr) + nfds * sizeof(int)];

    // initialize iovec[0] with struct PAL_HANDLE
    iov[0].iov_base = buffer;
    iov[0].iov_len = hdl_hdr.data_size;

    // set message header values
    hdr.msg_iov = iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = cbuf;
    hdr.msg_controllen = sizeof(struct cmsghdr) + sizeof(int) * nfds;

    ret = INLINE_SYSCALL(recvmsg, 3, ch, &hdr, 0);

    // if error was returned
    if (IS_ERR(ret) && ERRNO(ret) != EINTR && ERRNO(ret) != ERESTART)
        return -ERRNO(ret);

    struct cmsghdr * chdr = CMSG_FIRSTHDR(&hdr);
    if (!chdr || chdr->cmsg_type != SCM_RIGHTS)
        return -PAL_ERROR_INVAL;

    PAL_HANDLE handle = NULL;
    ret = handle_deserialize(&handle, buffer, hdl_hdr.data_size);
    if (ret < 0)
        return ret;

    int total_fds = (hdr.msg_controllen - sizeof(struct cmsghdr)) /
                    sizeof(int);
    int n = 0;
    for (int i = 0 ; i < MAX_FDS ; i++)
        if (hdl_hdr.fds & (1U << i)) {
            if (n < total_fds) {
                handle->generic.fds[i] = ((int *) CMSG_DATA(chdr))[n++];
            } else {
                HANDLE_HDR(handle)->flags &= ~(RFD(i)|WFD(i));
            }
        }

    if (IS_HANDLE_TYPE(handle, file)) {
        ret = INLINE_SYSCALL(lseek, 3, handle->file.fd, 0, SEEK_SET);
        if (!IS_ERR(ret))
            handle->file.offset = ret;
    }

    *cargo = handle;
    return 0;
}
