/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Labs */

/*!
 * \file
 *
 * This file contains the implementation of `/dev/null` and `/dev/zero` pseudo-files.
 */

#include "shim_fs.h"
#include "shim_fs_pseudo.h"
#include "stat.h"

ssize_t dev_null_read(struct shim_handle* hdl, void* buf, size_t count) {
    __UNUSED(hdl);
    __UNUSED(buf);
    __UNUSED(count);
    return 0;
}

ssize_t dev_null_write(struct shim_handle* hdl, const void* buf, size_t count) {
    __UNUSED(hdl);
    __UNUSED(buf);
    __UNUSED(count);
    return count;
}

off_t dev_null_seek(struct shim_handle* hdl, off_t offset, int whence) {
    __UNUSED(hdl);
    __UNUSED(offset);
    __UNUSED(whence);
    return 0;
}

int dev_null_truncate(struct shim_handle* hdl, uint64_t size) {
    __UNUSED(hdl);
    __UNUSED(size);
    return 0;
}

/* TODO move to null.c */
ssize_t dev_zero_read(struct shim_handle* hdl, void* buf, size_t count) {
    __UNUSED(hdl);
    memset(buf, 0, count);
    return count;
}
