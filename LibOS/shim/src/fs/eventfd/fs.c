/* Copyright (C) 2019 Intel Corporation
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
 * This file contains codes for implementation of 'eventfd' filesystem.
 */

#include <asm/fcntl.h>
#include <asm/unistd.h>
#include <errno.h>
#include <linux/fcntl.h>
#include <linux/stat.h>

#include <pal.h>
#include <shim_fs.h>
#include <shim_handle.h>
#include <shim_internal.h>

static ssize_t eventfd_read(struct shim_handle* hdl, void* buf, size_t count) {
    if (count < sizeof(uint64_t))
        return -EINVAL;

    PAL_NUM bytes = DkStreamRead(hdl->pal_handle, 0, count, buf, NULL, 0);

    if (bytes == PAL_STREAM_ERROR)
        return -PAL_ERRNO;

    return (ssize_t)bytes;
}

static ssize_t eventfd_write(struct shim_handle* hdl, const void* buf, size_t count) {
    if (count < sizeof(uint64_t))
        return -EINVAL;

    PAL_NUM bytes = DkStreamWrite(hdl->pal_handle, 0, count, (void*)buf, NULL);

    if (bytes == PAL_STREAM_ERROR)
        return -PAL_ERRNO;

    return (ssize_t)bytes;
}

static off_t eventfd_poll(struct shim_handle* hdl, int poll_type) {
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

struct shim_fs_ops eventfd_fs_ops = {
    .read  = &eventfd_read,
    .write = &eventfd_write,
    .poll  = &eventfd_poll,
};

struct shim_mount eventfd_builtin_fs = {
    .type   = URI_TYPE_EVENTFD,
    .fs_ops = &eventfd_fs_ops,
};
