/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2014 OSCAR lab, Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
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
#include <asm/stat.h>
#include <asm/socket.h>
#include <asm/poll.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <asm-errno.h>

void _DkPrintConsole (const void * buf, int size)
{
    INLINE_SYSCALL(write, 3, 2, buf, size);
}

bool stataccess (struct stat * stat, int acc)
{
    mode_t mode = stat->st_mode;

    if (pal_linux_config.uid && pal_linux_config.uid == stat->st_uid) {
        mode >>= 6;
        goto out;
    }

    if (pal_linux_config.gid && pal_linux_config.gid == stat->st_gid) {
        mode >>= 3;
        goto out;
    }

    if (!pal_linux_config.uid)
        mode >>= 6;

out:
    return (mode & acc);
}

/* _DkStreamUnmap for internal use. Unmap stream at certain memory address.
   The memory is unmapped as a whole.*/
int _DkStreamUnmap (void * addr, size_t size)
{
    /* Just let the kernel tell us if the mapping isn't good. */
    int ret = INLINE_SYSCALL(munmap, 2, addr, size);

    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    return 0;
}

// Header for DkSendHandle and DkRecvHandle
struct hdl_header {
    int type, body_size, nfds;
};

/* _DkSendHandle for internal use. Send a Pal Handle over the given
   process handle. Return 1 if success else return negative error code */
int _DkSendHandle (PAL_HANDLE hdl, PAL_HANDLE cargo)
{
    // Variables to store information for the message
    char * msg_buf[2] = { NULL, NULL };
    int msg_len[2] = { 0, 0 };
    int msg_nfds = 0, fds[2];
    struct hdl_header hdl_hdr;

    // ~ Check connection PAL_HANDLE - is of process type for sending handle
    // else fail
    if(__PAL_GET_TYPE(hdl) != pal_type_process)
        return -PAL_ERROR_BADHANDLE;

    // ~ Check cargo PAL_HANDLE - is allowed to be sent (White List checking
    // of cargo type)
    // ~ Also, Initialize common parameter formessage passing
    // Channel between parent and child
    switch(__PAL_GET_TYPE(cargo)) {
        case pal_type_file:
            msg_nfds = 1;
            fds[0] = cargo->file.fd;
            msg_len[0] = strlen(cargo->file.realpath) + 1;
            msg_buf[0] = (char *) cargo->file.realpath;
            break;
        case pal_type_pipe:
        case pal_type_pipesrv:
        case pal_type_pipecli:
            msg_nfds = 1;
            fds[0] = cargo->pipe.fd;
            break;
        case pal_type_pipeprv:
            msg_nfds = 2;
            fds[0] = cargo->pipeprv.fds[0];
            fds[1] = cargo->pipeprv.fds[1];
            break;
        case pal_type_dev:
            if (cargo->dev.fd_in != PAL_IDX_POISON)
                fds[msg_nfds++] = cargo->dev.fd_in;
            if (cargo->dev.fd_out != PAL_IDX_POISON)
                fds[msg_nfds++] = cargo->dev.fd_out;
            if (cargo->dev.realpath) {
                msg_len[0] = strlen(cargo->dev.realpath) + 1;
                msg_buf[0] = (char *) cargo->dev.realpath;
            }
            break;
        case pal_type_dir:
            msg_nfds = 1;
            fds[0] = cargo->dir.fd;
            if (cargo->dir.realpath) {
                msg_len[0] = strlen(cargo->dir.realpath) + 1;
                msg_buf[0] = (char *) cargo->dir.realpath;
            }
            break;
        case pal_type_tcp:
        case pal_type_tcpsrv:
        case pal_type_udp:
        case pal_type_udpsrv:

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
            msg_nfds = 1;
            fds[0] = cargo->sock.fd;
            int nmsg = 0;
            if (cargo->sock.bind) {
                msg_len[nmsg] = addr_size(cargo->sock.bind);
                msg_buf[nmsg] = cargo->sock.bind;
                nmsg++;
            }
            if (cargo->sock.conn) {
                msg_len[nmsg] = addr_size(cargo->sock.conn);
                msg_buf[nmsg] = cargo->sock.conn;
                nmsg++;
            }
            break;
        case pal_type_gipc:
            msg_nfds = 1;
            fds[0] = cargo->gipc.fd;
            break;
        default:
            return -PAL_ERROR_INVAL;
    }

    // ~ Initialize common parameter formessage passing
    // Channel between parent and child
    int ch = hdl->process.cargo;

    // Initialize header information
    // Common information for all the PAL_HANDLEs
    hdl_hdr.type = __PAL_GET_TYPE(cargo);
    hdl_hdr.body_size = msg_len[0] + msg_len[1];
    hdl_hdr.nfds = msg_nfds;

    // Declare variables required for sending the message
    struct msghdr hdr; // message header
    struct cmsghdr * chdr; //control message header
    struct iovec iov[3]; // IO Vector

    iov[0].iov_base = &hdl_hdr;
    iov[0].iov_len = sizeof(struct hdl_header);
    hdr.msg_name = NULL;
    hdr.msg_namelen = 0;
    hdr.msg_iov = iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = NULL;
    hdr.msg_controllen = 0;
    hdr.msg_flags = 0;

    int ret = INLINE_SYSCALL(sendmsg, 3, ch, &hdr, MSG_NOSIGNAL);

    // Unlock is error
    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    /* Message Body Composition:
       IOVEC[0]: PAL_HANDLE
       IOVEC[1..n]: Additional handle member follow
       Control Message: file descriptors */

    // Control message buffer with added space for 2 fds (ie. max size
    // that it will have)
    char cbuf[sizeof(struct cmsghdr) + 2 * sizeof(int)];

    // Initialize iovec[0] with struct PAL_HANDLE
    iov[0].iov_base = cargo;
    iov[0].iov_len = sizeof(union pal_handle);

    // Initialize iovec[1] for additional element with message buffer
    iov[1].iov_base = msg_len[0] ? msg_buf[0] : NULL;
    iov[1].iov_len = msg_len[0] ? : 0;

    // Initialize iovec[2] for additional element with message buffer
    iov[2].iov_base = msg_len[1] ? msg_buf[0] : NULL;
    iov[2].iov_len = msg_len[1] ? : 0;

    hdr.msg_iov = iov;
    hdr.msg_iovlen = msg_len[0] ? (msg_len[1] ? 3 : 2) : 1;
    hdr.msg_control = cbuf; // Control Message Buffer
    hdr.msg_controllen = sizeof(struct cmsghdr) + sizeof(int) * msg_nfds;

    // Fill control message infomation for the file descriptors
    // Check hdr.msg_controllen >= sizeof(struct cmsghdr) to point to
    // cbuf, which is redundant based on the above code as we have
    // statically allocated memory.
    // or (struct cmsghdr*) cbuf
    chdr = CMSG_FIRSTHDR(&hdr); // Pointer to msg_control
    chdr->cmsg_level = SOL_SOCKET; // Originating Protocol
    chdr->cmsg_type = SCM_RIGHTS; // Protocol Specific Type
    // Length of control message = sizeof(struct cmsghdr) + nfds
    chdr->cmsg_len = CMSG_LEN(sizeof(int) * msg_nfds);

    // Copy the fds below control header
    memcpy(CMSG_DATA(chdr), fds, sizeof(int) * msg_nfds);

    // Also, Update main header with control message length (duplicate)
    hdr.msg_controllen = chdr->cmsg_len;

    //  Send message
    ret = INLINE_SYSCALL(sendmsg, 3, ch, &hdr, 0);

    return IS_ERR(ret) ? -PAL_ERROR_DENIED : 0;
}

/* _DkRecvHandle for internal use. Receive and return a PAL_HANDLE over the
   given PAL_HANDLE else return negative value. */
int _DkReceiveHandle(PAL_HANDLE hdl, PAL_HANDLE cargo)
{
    struct hdl_header hdl_hdr;

    // ~ Check connection PAL_HANDLE - is of process type for sending handle
    // else fail
    if (__PAL_GET_TYPE(hdl) != pal_type_process)
        return -PAL_ERROR_BADHANDLE;

    // ~ Initialize common parameter for message passing
    // Channel between parent and child
    int ch = hdl->process.cargo;

    struct msghdr hdr;
    struct iovec iov[2];

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
    int msg_len = hdl_hdr.body_size, msg_nfds = hdl_hdr.nfds;
    void * msg_buf = msg_len ? malloc(msg_len) : NULL;
    // make in stack
    int * fds = __alloca(sizeof(int) * msg_nfds);

    // receive PAL_HANDLE contents in the body
    char cbuf[sizeof(struct cmsghdr) + 2 * sizeof(int)];

    // initialize iovec[0] with struct PAL_HANDLE
    iov[0].iov_base = cargo;
    iov[0].iov_len = sizeof(union pal_handle);

    // initialize iovec[1] for additional element with message buffer
    iov[1].iov_base = msg_buf;
    iov[1].iov_len = msg_len;

    // clear body memory
    memset(&hdr, 0, sizeof(struct msghdr));

    // set message header values
    hdr.msg_iov = iov;
    hdr.msg_iovlen = msg_len ? 2 : 1;
    hdr.msg_control = cbuf;
    hdr.msg_controllen = sizeof(struct cmsghdr) + sizeof(int) *
                         msg_nfds;

    ret = INLINE_SYSCALL(recvmsg, 3, ch, &hdr, 0);

    if (!IS_ERR(ret)) {
        struct cmsghdr * chdr = CMSG_FIRSTHDR(&hdr);
        if (chdr &&
            chdr->cmsg_type == SCM_RIGHTS) {
            msg_nfds = (hdr.msg_controllen - sizeof(struct cmsghdr)) /
                       sizeof(int);
            memcpy(fds, CMSG_DATA(chdr), sizeof(int) * msg_nfds);
        } else {
            msg_nfds = 0;
        }
    }

    // if error was returned
    if (IS_ERR(ret) && ERRNO(ret) != EINTR && ERRNO(ret) != ERESTART)
        return -ERRNO(ret);

    // recreate PAL_HANDLE based on type
    switch(hdl_hdr.type) {
        case pal_type_file: {
            if (msg_nfds < 1)
                return -PAL_ERROR_BADHANDLE;
            cargo->file.fd = fds[0];
            cargo->file.realpath = remalloc(msg_buf, msg_len);
            break;
        }
        case pal_type_pipe:
        case pal_type_pipesrv:
        case pal_type_pipecli:
            if (msg_nfds < 1)
                return -PAL_ERROR_BADHANDLE;
            cargo->pipe.fd = fds[0];
            break;
        case pal_type_pipeprv:
            if (msg_nfds < 2)
                return -PAL_ERROR_BADHANDLE;
            cargo->pipeprv.fds[0] = fds[0];
            cargo->pipeprv.fds[1] = fds[1];
            break;
        case pal_type_dev: {
            int i = 0;
            if (cargo->dev.fd_in != PAL_IDX_POISON) {
                if (msg_nfds < 1)
                    return -PAL_ERROR_BADHANDLE;
                cargo->dev.fd_in = fds[i++];
                msg_nfds--;
            }
            if (cargo->dev.fd_out != PAL_IDX_POISON) {
                if (msg_nfds < 1)
                    return -PAL_ERROR_BADHANDLE;
                cargo->dev.fd_out = fds[i++];
                msg_nfds--;
            }
            cargo->file.realpath = remalloc(msg_buf, msg_len);;
            break;
        }
        case pal_type_dir: {
            if (msg_nfds < 1)
                return -PAL_ERROR_BADHANDLE;
            cargo->dir.fd = fds[0];
            cargo->dir.realpath = remalloc(msg_buf, msg_len);
            break;
        }
        case pal_type_tcp:
        case pal_type_tcpsrv:
        case pal_type_udp: {
            void * addr = msg_buf;
            if (cargo->sock.bind) {
                int len = addr_size(addr);
                if (addr + len > msg_buf + msg_len)
                    return -PAL_ERROR_OVERFLOW;
                cargo->sock.bind = remalloc(addr, len);
                addr += len;
            }
            if (cargo->sock.conn) {
                int len = addr_size(addr);
                if (addr + len > msg_buf + msg_len)
                    return -PAL_ERROR_OVERFLOW;
                cargo->sock.conn = remalloc(addr, len);
                addr += len;
            }
        }
        case pal_type_udpsrv:
            if (msg_nfds < 1)
                return -PAL_ERROR_BADHANDLE;
            cargo->sock.fd = fds[0];
            break;
        case pal_type_gipc:
            if (msg_nfds < 1)
                return -PAL_ERROR_BADHANDLE;
            cargo->gipc.fd = fds[0];
            break;
        default :
            return -PAL_ERROR_BADHANDLE;
    }

    return 0;
}
