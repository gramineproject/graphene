/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains code for implementation of 'pipe' filesystem.
 */

#include <asm/fcntl.h>
#include <asm/mman.h>
#include <asm/unistd.h>
#include <errno.h>
#include <linux/fcntl.h>

#include "pal.h"
#include "pal_error.h"
#include "perm.h"
#include "shim_fs.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_lock.h"
#include "shim_process.h"
#include "shim_signal.h"
#include "shim_thread.h"
#include "stat.h"

static ssize_t pipe_read(struct shim_handle* hdl, void* buf, size_t count) {
    assert(hdl->type == TYPE_PIPE);
    if (!hdl->info.pipe.ready_for_ops)
        return -EACCES;

    size_t orig_count = count;
    int ret = DkStreamRead(hdl->pal_handle, 0, &count, buf, NULL, 0);
    ret = pal_to_unix_errno(ret);
    maybe_epoll_et_trigger(hdl, ret, /*in=*/true, ret == 0 ? count < orig_count : false);
    if (ret < 0) {
        return ret;
    }

    return (ssize_t)count;
}

static ssize_t pipe_write(struct shim_handle* hdl, const void* buf, size_t count) {
    assert(hdl->type == TYPE_PIPE);
    if (!hdl->info.pipe.ready_for_ops)
        return -EACCES;

    size_t orig_count = count;
    int ret = DkStreamWrite(hdl->pal_handle, 0, &count, (void*)buf, NULL);
    ret = pal_to_unix_errno(ret);
    maybe_epoll_et_trigger(hdl, ret, /*in=*/false, ret == 0 ? count < orig_count : false);
    if (ret < 0) {
        if (ret == -EPIPE) {
            siginfo_t info = {
                .si_signo = SIGPIPE,
                .si_pid = g_process.pid,
                .si_code = SI_USER,
            };
            if (kill_current_proc(&info) < 0) {
                log_error("pipe_write: failed to deliver a signal");
            }
        }
        return ret;
    }

    return (ssize_t)count;
}

static int pipe_hstat(struct shim_handle* hdl, struct stat* stat) {
    /* XXX: Is any of this right?
     * Shouldn't we be using hdl to figure something out?
     * if stat is NULL, should we not return -EFAULT?
     */
    __UNUSED(hdl);
    if (!stat)
        return 0;

    struct shim_thread* thread = get_cur_thread();

    stat->st_dev     = (dev_t)0;           /* ID of device containing file */
    stat->st_ino     = (ino_t)0;           /* inode number */
    stat->st_nlink   = (nlink_t)0;         /* number of hard links */
    stat->st_uid     = (uid_t)thread->uid; /* user ID of owner */
    stat->st_gid     = (gid_t)thread->gid; /* group ID of owner */
    stat->st_rdev    = (dev_t)0;           /* device ID (if special file) */
    stat->st_size    = (off_t)0;           /* total size, in bytes */
    stat->st_blksize = 0;                  /* blocksize for file system I/O */
    stat->st_blocks  = 0;                  /* number of 512B blocks allocated */
    stat->st_atime   = (time_t)0;          /* access time */
    stat->st_mtime   = (time_t)0;          /* last modification */
    stat->st_ctime   = (time_t)0;          /* last status change */
    stat->st_mode    = PERM_rw_______ | S_IFIFO;

    return 0;
}

static int pipe_poll(struct shim_handle* hdl, int poll_type) {
    int ret = 0;

    assert(hdl->type == TYPE_PIPE);
    if (!hdl->info.pipe.ready_for_ops)
        return -EACCES;

    lock(&hdl->lock);

    if (!hdl->pal_handle) {
        ret = -EBADF;
        goto out;
    }

    PAL_STREAM_ATTR attr;
    int query_ret = DkStreamAttributesQueryByHandle(hdl->pal_handle, &attr);
    if (query_ret < 0) {
        ret = pal_to_unix_errno(query_ret);
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
    unlock(&hdl->lock);
    return ret;
}

static int pipe_setflags(struct shim_handle* hdl, int flags) {
    if (!hdl->pal_handle)
        return 0;

    PAL_STREAM_ATTR attr;

    int ret = DkStreamAttributesQueryByHandle(hdl->pal_handle, &attr);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }

    if (attr.nonblocking) {
        if (flags & O_NONBLOCK)
            return 0;

        attr.nonblocking = PAL_FALSE;
    } else {
        if (!(flags & O_NONBLOCK))
            return 0;

        attr.nonblocking = PAL_TRUE;
    }

    ret = DkStreamAttributesSetByHandle(hdl->pal_handle, &attr);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }

    return 0;
}

static int fifo_open(struct shim_handle* hdl, struct shim_dentry* dent, int flags) {
    assert(hdl);
    assert(dent && dent->data && dent->fs);
    static_assert(sizeof(dent->data) >= sizeof(uint64_t),
                  "dentry's data must be at least 8B in size");

    /* FIXME: man 7 fifo says "[with non-blocking flag], opening for write-only fails with ENXIO
     *        unless the other end has already been opened". We cannot enforce this failure since
     *        Graphene doesn't know whether the other process already opened this FIFO. */

    if (flags & O_RDWR) {
        /* POSIX disallows FIFOs opened for read-write, but Linux allows it. We must choose only
         * one end (read or write) in our emulation, so we treat such FIFOs as read-only. This
         * covers most apps seen in the wild (in particular, LTP apps). */
        log_warning("FIFO (named pipe) '%s' cannot be opened in read-write mode in Graphene. "
                    "Treating it as read-only.", dent->mount->path);
        flags = O_RDONLY;
    }

    int fd = -1;
    if (flags & O_WRONLY) {
        /* write end of FIFO is stashed in upper bits of dentry's data; invalidate afterwards */
        fd = (uint32_t)((uint64_t)dent->data >> 32);
        dent->data = (void*)((uint64_t)dent->data | 0xFFFFFFFF00000000ULL);
    } else {
        /* read end of FIFO is stashed in lower bits of dentry's data; invalidate afterwards */
        fd = (uint32_t)((uint64_t)dent->data);
        dent->data = (void*)((uint64_t)dent->data | 0x00000000FFFFFFFFULL);
    }

    if (fd == -1) {
        /* fd is invalid, happens if app tries to open the same FIFO end twice; this is ok in
         * normal Linux but Graphene uses TLS-encrypted pipes which are inherently point-to-point;
         * if this changes, should remove this error case (see GitHub issue #1417) */
        return -EOPNOTSUPP;
    }

    struct shim_handle* fifo_hdl = get_fd_handle(fd, /*fd_flags=*/NULL, /*map=*/NULL);
    if (!fifo_hdl) {
        return -ENOENT;
    }

    if (flags & O_NONBLOCK) {
        /* FIFOs were created in blocking mode (see shim_do_mknodat), change their attributes */
        int ret = pipe_setflags(fifo_hdl, flags);
        if (ret < 0) {
            put_handle(fifo_hdl);
            return ret;
        }
    }

    /* rewire new hdl to contents of intermediate FIFO hdl */
    assert(fifo_hdl->type == TYPE_PIPE);

    hdl->type       = fifo_hdl->type;
    hdl->acc_mode   = fifo_hdl->acc_mode;
    hdl->info       = fifo_hdl->info;
    hdl->pal_handle = fifo_hdl->pal_handle;
    qstrcopy(&hdl->uri, &fifo_hdl->uri);

    hdl->info.pipe.ready_for_ops = true;

    fifo_hdl->pal_handle = NULL; /* ownership of PAL handle is transferred to hdl */

    /* can remove intermediate FIFO hdl and its fd now */
    struct shim_handle* tmp = detach_fd_handle(fd, NULL, NULL);
    assert(tmp == fifo_hdl);
    put_handle(tmp);      /* matches detach_fd_handle() */
    put_handle(fifo_hdl); /* matches get_fd_handle() */

    return 0;
}

static struct shim_fs_ops pipe_fs_ops = {
    .read     = &pipe_read,
    .write    = &pipe_write,
    .hstat    = &pipe_hstat,
    .poll     = &pipe_poll,
    .setflags = &pipe_setflags,
};

static struct shim_fs_ops fifo_fs_ops = {
    .read     = &pipe_read,
    .write    = &pipe_write,
    .poll     = &pipe_poll,
    .setflags = &pipe_setflags,
};

static struct shim_d_ops fifo_d_ops = {
    .open = &fifo_open,
};

struct shim_fs pipe_builtin_fs = {
    .name   = "pipe",
    .fs_ops = &pipe_fs_ops,
};

struct shim_fs fifo_builtin_fs = {
    .name   = "fifo",
    .fs_ops = &fifo_fs_ops,
    .d_ops  = &fifo_d_ops,
};
