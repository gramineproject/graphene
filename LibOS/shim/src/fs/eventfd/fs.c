/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2019 Intel Corporation */

/*
 * This file contains code for implementation of 'eventfd' filesystem.
 */

#include <asm/fcntl.h>
#include <asm/unistd.h>
#include <errno.h>
#include <linux/fcntl.h>

#include "pal.h"
#include "shim_fs.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_lock.h"

static ssize_t eventfd_read(struct shim_handle* hdl, void* buf, size_t count) {
    if (count < sizeof(uint64_t))
        return -EINVAL;

    size_t orig_count = count;
    int ret = DkStreamRead(hdl->pal_handle, 0, &count, buf, NULL, 0);
    ret = pal_to_unix_errno(ret);
    maybe_epoll_et_trigger(hdl, ret, /*in=*/true, ret == 0 ? count < orig_count : false);
    if (ret < 0) {
        return ret;
    }

    return (ssize_t)count;
}

static ssize_t eventfd_write(struct shim_handle* hdl, const void* buf, size_t count) {
    if (count < sizeof(uint64_t))
        return -EINVAL;

    size_t orig_count = count;
    int ret = DkStreamWrite(hdl->pal_handle, 0, &count, (void*)buf, NULL);
    ret = pal_to_unix_errno(ret);
    maybe_epoll_et_trigger(hdl, ret, /*in=*/false, ret == 0 ? count < orig_count : false);
    if (ret < 0) {
        return ret;
    }

    return (ssize_t)count;
}

static int eventfd_poll(struct shim_handle* hdl, int poll_type) {
    int ret = 0;

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

struct shim_fs_ops eventfd_fs_ops = {
    .read  = &eventfd_read,
    .write = &eventfd_write,
    .poll  = &eventfd_poll,
};

struct shim_fs eventfd_builtin_fs = {
    .name   = "eventfd",
    .fs_ops = &eventfd_fs_ops,
};
