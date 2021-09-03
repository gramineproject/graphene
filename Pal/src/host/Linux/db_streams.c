/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs to open, read, write and get attribute of streams.
 */

#include <asm/errno.h>
#include <asm/fcntl.h>
#include <asm/poll.h>
#include <asm/socket.h>
#include <linux/msg.h>
#include <linux/socket.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "api.h"
#include "linux_utils.h"
#include "pal.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_security.h"
#include "perm.h"
#include "stat.h"

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
    mode_t mode = stat->st_mode;

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

int handle_set_cloexec(PAL_HANDLE handle, bool enable) {
    for (int i = 0; i < MAX_FDS; i++)
        if (HANDLE_HDR(handle)->flags & (RFD(i) | WFD(i))) {
            long flags = enable ? FD_CLOEXEC : 0;
            int ret = DO_SYSCALL(fcntl, handle->generic.fds[i], F_SETFD, flags);
            if (ret < 0 && ret != -EBADF)
                return -PAL_ERROR_DENIED;
        }

    return 0;
}

/* _DkStreamUnmap for internal use. Unmap stream at certain memory address.
   The memory is unmapped as a whole.*/
int _DkStreamUnmap(void* addr, uint64_t size) {
    /* Just let the kernel tell us if the mapping isn't good. */
    int ret = DO_SYSCALL(munmap, addr, size);

    if (ret < 0)
        return -PAL_ERROR_DENIED;

    return 0;
}

int handle_serialize(PAL_HANDLE handle, void** data) {
    const void* d1;
    const void* d2;
    size_t dsz1 = 0;
    size_t dsz2 = 0;

    /* find fields to serialize (depends on the handle type) and assign them to d1/d2; note that
     * no handle type has more than two such fields, and some have none at all */
    switch (PAL_GET_TYPE(handle)) {
        case PAL_TYPE_FILE:
            d1   = handle->file.realpath;
            dsz1 = strlen(handle->file.realpath) + 1;
            break;
        case PAL_TYPE_PIPE:
        case PAL_TYPE_PIPESRV:
        case PAL_TYPE_PIPECLI:
        case PAL_TYPE_PIPEPRV:
            /* pipes have no fields to serialize */
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
        case PAL_TYPE_EVENTFD:
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

    *data = buffer;
    return hdlsz + dsz1 + dsz2;
}

int handle_deserialize(PAL_HANDLE* handle, const void* data, size_t size) {
    PAL_HANDLE hdl = malloc(size);
    if (!hdl)
        return -PAL_ERROR_NOMEM;

    memcpy(hdl, data, size);
    size_t hdlsz = handle_size(hdl);

    /* update handle fields to point to correct contents (located right after handle itself) */
    switch (PAL_GET_TYPE(hdl)) {
        case PAL_TYPE_FILE:
            hdl->file.realpath = hdl->file.realpath ? (PAL_STR)hdl + hdlsz : NULL;
            break;
        case PAL_TYPE_PIPE:
        case PAL_TYPE_PIPESRV:
        case PAL_TYPE_PIPECLI:
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
        case PAL_TYPE_EVENTFD:
            break;
        default:
            return -PAL_ERROR_BADHANDLE;
    }

    *handle = hdl;
    return 0;
}

/*!
 * \brief Send `cargo` handle to a process identified via `hdl` handle.
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
    struct msghdr message_hdr = {0};
    struct iovec iov[1];

    iov[0].iov_base    = &hdl_hdr;
    iov[0].iov_len     = sizeof(hdl_hdr);
    message_hdr.msg_iov    = iov;
    message_hdr.msg_iovlen = 1;

    ret = DO_SYSCALL(sendmsg, fd, &message_hdr, MSG_NOSIGNAL);
    if (ret < 0) {
        free(hdl_data);
        return unix_to_pal_error(ret);
    }

    /* construct ancillary data of FDs-to-transfer in a control message */
    char control_buf[sizeof(struct cmsghdr) + MAX_FDS * sizeof(int)];
    message_hdr.msg_control    = control_buf;
    message_hdr.msg_controllen = sizeof(control_buf);

    struct cmsghdr* control_hdr = CMSG_FIRSTHDR(&message_hdr);
    control_hdr->cmsg_level = SOL_SOCKET;
    control_hdr->cmsg_type  = SCM_RIGHTS;
    control_hdr->cmsg_len   = CMSG_LEN(sizeof(int) * nfds);
    memcpy(CMSG_DATA(control_hdr), fds, sizeof(int) * nfds);

    message_hdr.msg_controllen = control_hdr->cmsg_len;

    /* finally send the serialized cargo as payload and FDs-to-transfer as ancillary data */
    iov[0].iov_base = hdl_data;
    iov[0].iov_len  = hdl_data_size;
    message_hdr.msg_iov    = iov;
    message_hdr.msg_iovlen = 1;

    ret = DO_SYSCALL(sendmsg, fd, &message_hdr, 0);
    if (ret < 0) {
        free(hdl_data);
        return unix_to_pal_error(ret);
    }

    free(hdl_data);
    return ret < 0 ? unix_to_pal_error(ret) : 0;
}

/*!
 * \brief Receive `cargo` handle from a process identified via `hdl` handle.
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
    struct msghdr message_hdr = {0};
    struct iovec iov[1];

    iov[0].iov_base = &hdl_hdr;
    iov[0].iov_len  = sizeof(hdl_hdr);
    message_hdr.msg_iov    = iov;
    message_hdr.msg_iovlen = 1;

    ret = DO_SYSCALL(recvmsg, fd, &message_hdr, 0);
    if (ret < 0)
        return unix_to_pal_error(ret);

    if ((size_t)ret != sizeof(hdl_hdr)) {
        /* This check is to shield from a Iago attack. We know that sendmsg() in _DkSendHandle()
         * transfers the message atomically, and that our recvmsg() receives it atomically. So
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

    char control_buf[sizeof(struct cmsghdr) + nfds * sizeof(int)];
    message_hdr.msg_control    = control_buf;
    message_hdr.msg_controllen = sizeof(control_buf);

    /* finally receive the serialized cargo as payload and FDs-to-transfer as ancillary data */
    char hdl_data[hdl_hdr.data_size];

    iov[0].iov_base = hdl_data;
    iov[0].iov_len  = hdl_hdr.data_size;
    message_hdr.msg_iov    = iov;
    message_hdr.msg_iovlen = 1;

    ret = DO_SYSCALL(recvmsg, fd, &message_hdr, 0);
    if (ret < 0)
        return unix_to_pal_error(ret);

    /* deserialize cargo handle from a blob hdl_data */
    PAL_HANDLE handle = NULL;
    ret = handle_deserialize(&handle, hdl_data, hdl_hdr.data_size);
    if (ret < 0)
        return ret;

    /* restore cargo handle's FDs from the received FDs-to-transfer */
    struct cmsghdr* control_hdr = CMSG_FIRSTHDR(&message_hdr);
    if (!control_hdr || control_hdr->cmsg_type != SCM_RIGHTS)
        return -PAL_ERROR_DENIED;

    int fds_idx = 0;
    int* fds = (int*)CMSG_DATA(control_hdr);

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
        ret = DO_SYSCALL(close, g_log_fd);
        g_log_fd = PAL_LOG_DEFAULT_FD;
        if (ret < 0)
            return unix_to_pal_error(ret);
    }

    ret = DO_SYSCALL(open, path, O_WRONLY | O_APPEND | O_CREAT, PERM_rw_______);
    if (ret < 0)
        return unix_to_pal_error(ret);
    g_log_fd = ret;
    return 0;
}

int _DkDebugLog(const void* buf, size_t size) {
    if (g_log_fd < 0)
        return -PAL_ERROR_BADHANDLE;

    int ret = write_all(g_log_fd, buf, size);
    if (ret < 0)
        return unix_to_pal_error(ret);
    return 0;
}
