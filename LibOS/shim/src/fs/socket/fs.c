/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains code for implementation of 'socket' filesystem.
 */

#include <asm/fcntl.h>
#include <asm/mman.h>
#include <asm/unistd.h>
#include <errno.h>
#include <linux/fcntl.h>

#include "pal.h"
#include "pal_error.h"
#include "shim_fs.h"
#include "shim_internal.h"
#include "shim_lock.h"
#include "shim_process.h"
#include "shim_signal.h"
#include "stat.h"

static int socket_close(struct shim_handle* hdl) {
    /* XXX: Shouldn't this do something? */
    __UNUSED(hdl);
    return 0;
}

static ssize_t socket_read(struct shim_handle* hdl, void* buf, size_t count) {
    struct shim_sock_handle* sock = &hdl->info.sock;

    lock(&hdl->lock);

    if (sock->sock_type == SOCK_STREAM && sock->sock_state != SOCK_ACCEPTED &&
        sock->sock_state != SOCK_CONNECTED && sock->sock_state != SOCK_BOUNDCONNECTED) {
        sock->error = ENOTCONN;
        unlock(&hdl->lock);
        return -ENOTCONN;
    }

    if (sock->sock_type == SOCK_DGRAM && sock->sock_state != SOCK_CONNECTED &&
        sock->sock_state != SOCK_BOUNDCONNECTED) {
        sock->error = EDESTADDRREQ;
        unlock(&hdl->lock);
        return -EDESTADDRREQ;
    }

    unlock(&hdl->lock);

    PAL_NUM bytes = DkStreamRead(hdl->pal_handle, 0, count, buf, NULL, 0);

    if (bytes == PAL_STREAM_ERROR)
        switch (PAL_NATIVE_ERRNO()) {
            case PAL_ERROR_ENDOFSTREAM:
                return 0;
            default: {
                int err = PAL_ERRNO();
                lock(&hdl->lock);
                sock->error = err;
                unlock(&hdl->lock);
                return -err;
            }
        }

    return (ssize_t)bytes;
}

static ssize_t socket_write(struct shim_handle* hdl, const void* buf, size_t count) {
    struct shim_sock_handle* sock = &hdl->info.sock;

    lock(&hdl->lock);

    if (sock->sock_type == SOCK_STREAM && sock->sock_state != SOCK_ACCEPTED &&
        sock->sock_state != SOCK_CONNECTED && sock->sock_state != SOCK_BOUNDCONNECTED) {
        sock->error = ENOTCONN;
        unlock(&hdl->lock);
        return -ENOTCONN;
    }

    if (sock->sock_type == SOCK_DGRAM && sock->sock_state != SOCK_CONNECTED &&
        sock->sock_state != SOCK_BOUNDCONNECTED) {
        sock->error = EDESTADDRREQ;
        unlock(&hdl->lock);
        return -EDESTADDRREQ;
    }

    unlock(&hdl->lock);

    PAL_NUM bytes = DkStreamWrite(hdl->pal_handle, 0, count, (void*)buf, NULL);

    if (bytes == PAL_STREAM_ERROR) {
        int err = PAL_ERRNO();
        if (err == EPIPE) {
            siginfo_t info = {
                .si_signo = SIGPIPE,
                .si_pid = g_process.pid,
                .si_code = SI_USER,
            };
            if (kill_current_proc(&info) < 0) {
                debug("socket_write: failed to deliver a signal\n");
            }
        }

        lock(&hdl->lock);
        sock->error = err;
        unlock(&hdl->lock);
        return -err;
    }

    return (ssize_t)bytes;
}

static int socket_hstat(struct shim_handle* hdl, struct stat* stat) {
    if (!stat)
        return 0;

    PAL_STREAM_ATTR attr;

    if (!DkStreamAttributesQueryByHandle(hdl->pal_handle, &attr))
        return -PAL_ERRNO();

    memset(stat, 0, sizeof(struct stat));

    stat->st_ino  = 0;
    stat->st_size = (off_t)attr.pending_size;
    stat->st_mode = S_IFSOCK;

    return 0;
}

static int socket_checkout(struct shim_handle* hdl) {
    hdl->fs = NULL;
    return 0;
}

static off_t socket_poll(struct shim_handle* hdl, int poll_type) {
    struct shim_sock_handle* sock = &hdl->info.sock;
    off_t ret = 0;

    lock(&hdl->lock);

    if (poll_type & FS_POLL_RD) {
        if (sock->sock_type == SOCK_STREAM) {
            if (sock->sock_state == SOCK_CREATED || sock->sock_state == SOCK_BOUND ||
                sock->sock_state == SOCK_SHUTDOWN) {
                ret = -ENOTCONN;
                goto out;
            }
        }

        if (sock->sock_type == SOCK_DGRAM && sock->sock_state == SOCK_SHUTDOWN) {
            ret = -ENOTCONN;
            goto out;
        }
    }

    if (poll_type & FS_POLL_WR) {
        if (sock->sock_type == SOCK_STREAM) {
            if (sock->sock_state == SOCK_CREATED || sock->sock_state == SOCK_BOUND ||
                sock->sock_state == SOCK_LISTENED || sock->sock_state == SOCK_SHUTDOWN) {
                ret = -ENOTCONN;
                goto out;
            }
        }

        if (sock->sock_type == SOCK_DGRAM && sock->sock_state == SOCK_SHUTDOWN) {
            ret = -ENOTCONN;
            goto out;
        }
    }

    if (!hdl->pal_handle) {
        ret = -EBADF;
        goto out;
    }

    PAL_STREAM_ATTR attr;
    if (!DkStreamAttributesQueryByHandle(hdl->pal_handle, &attr)) {
        ret = -PAL_ERRNO();
        goto out;
    }

    if (poll_type == FS_POLL_SZ) {
        ret = attr.pending_size;
        goto out;
    }

    ret = 0;
    if (attr.disconnected)
        ret |= FS_POLL_ER;
    if ((poll_type & FS_POLL_RD) && attr.readable)
        ret |= FS_POLL_RD;
    if ((poll_type & FS_POLL_WR) && attr.writable)
        ret |= FS_POLL_WR;

out:
    if (ret < 0) {
        debug("socket_poll failed (%ld)\n", ret);
        sock->error = -ret;
    }

    unlock(&hdl->lock);
    return ret;
}

static int socket_setflags(struct shim_handle* hdl, int flags) {
    if (!hdl->pal_handle)
        return 0;

    PAL_STREAM_ATTR attr;

    if (!DkStreamAttributesQueryByHandle(hdl->pal_handle, &attr))
        return -PAL_ERRNO();

    if (attr.nonblocking) {
        if (flags & O_NONBLOCK)
            return 0;

        attr.nonblocking = PAL_FALSE;
    } else {
        if (!(flags & O_NONBLOCK))
            return 0;

        attr.nonblocking = PAL_TRUE;
    }

    if (!DkStreamAttributesSetByHandle(hdl->pal_handle, &attr))
        return -PAL_ERRNO();

    return 0;
}

struct shim_fs_ops socket_fs_ops = {
    .close    = &socket_close,
    .read     = &socket_read,
    .write    = &socket_write,
    .hstat    = &socket_hstat,
    .checkout = &socket_checkout,
    .poll     = &socket_poll,
    .setflags = &socket_setflags,
};

struct shim_mount socket_builtin_fs = {
    .type   = "socket",
    .fs_ops = &socket_fs_ops,
};
