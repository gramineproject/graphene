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
 * fs.c
 *
 * This file contains codes for implementation of 'pipe' filesystem.
 */

#define __KERNEL__

#include <asm/fcntl.h>
#include <asm/mman.h>
#include <asm/prctl.h>
#include <asm/unistd.h>
#include <errno.h>
#include <linux/fcntl.h>
#include <linux/stat.h>

#include <pal.h>
#include <pal_debug.h>
#include <pal_error.h>
#include <shim_fs.h>
#include <shim_handle.h>
#include <shim_internal.h>
#include <shim_profile.h>
#include <shim_thread.h>

static ssize_t pipe_read(struct shim_handle* hdl, void* buf, size_t count) {
    PAL_NUM bytes = DkStreamRead(hdl->pal_handle, 0, count, buf, NULL, 0);

    if (bytes == PAL_STREAM_ERROR)
        return -PAL_ERRNO;

    return (ssize_t)bytes;
}

static ssize_t pipe_write(struct shim_handle* hdl, const void* buf, size_t count) {
    PAL_NUM bytes = DkStreamWrite(hdl->pal_handle, 0, count, (void*)buf, NULL);

    if (bytes == PAL_STREAM_ERROR)
        return -PAL_ERRNO;

    return (ssize_t)bytes;
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
    stat->st_mode    = S_IRUSR | S_IWUSR | S_IFIFO;

    return 0;
}

static int pipe_checkout(struct shim_handle* hdl) {
    hdl->fs = NULL;
    return 0;
}

static off_t pipe_poll(struct shim_handle* hdl, int poll_type) {
    off_t ret = 0;

    lock(&hdl->lock);

    if (!hdl->pal_handle) {
        ret = -EBADF;
        goto out;
    }

    PAL_STREAM_ATTR attr;
    if (!DkStreamAttributesQueryByHandle(hdl->pal_handle, &attr)) {
        ret = -PAL_ERRNO;
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
    unlock(&hdl->lock);
    return ret;
}

static int pipe_setflags(struct shim_handle* hdl, int flags) {
    if (!hdl->pal_handle)
        return 0;

    PAL_STREAM_ATTR attr;

    if (!DkStreamAttributesQueryByHandle(hdl->pal_handle, &attr))
        return -PAL_ERRNO;

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
        return -PAL_ERRNO;

    return 0;
}

struct shim_fs_ops pipe_fs_ops = {
    .read     = &pipe_read,
    .write    = &pipe_write,
    .hstat    = &pipe_hstat,
    .checkout = &pipe_checkout,
    .poll     = &pipe_poll,
    .setflags = &pipe_setflags,
};

struct shim_mount pipe_builtin_fs = {
    .type   = URI_TYPE_PIPE,
    .fs_ops = &pipe_fs_ops,
};
