/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Labs */

/*!
 * \file
 *
 * This file contains the implementation of `/dev/random` and `/dev/urandom` pseudo-files.
 */

#include "shim_fs.h"
#include "stat.h"

static ssize_t dev_random_read(struct shim_handle* hdl, void* buf, size_t count) {
    __UNUSED(hdl);
    ssize_t ret = DkRandomBitsRead(buf, count);

    if (ret < 0)
        return -convert_pal_errno(-ret);
    return count;
}

static ssize_t dev_random_write(struct shim_handle* hdl, const void* buf, size_t count) {
    /* writes in /dev/random add entropy in normal Linux, but not implemented in Graphene */
    __UNUSED(hdl);
    __UNUSED(buf);
    __UNUSED(count);
    return count;
}

static int dev_random_mode(const char* name, mode_t* mode) {
    __UNUSED(name);
    *mode = FILE_RW_MODE | S_IFCHR;
    return 0;
}

static int dev_random_stat(const char* name, struct stat* buf) {
    __UNUSED(name);
    memset(buf, 0, sizeof(*buf));

    buf->st_mode = FILE_RW_MODE | S_IFCHR;
    return 0;
}

static int dev_random_hstat(struct shim_handle* hdl, struct stat* buf) {
    __UNUSED(hdl);
    return dev_random_stat(/*name=*/NULL, buf);
}

static int dev_random_open(struct shim_handle* hdl, const char* name, int flags) {
    __UNUSED(name);
    __UNUSED(flags);

    struct shim_dev_ops ops = {.read  = &dev_random_read,
                               .write = &dev_random_write,
                               .mode  = &dev_random_mode,
                               .stat  = &dev_random_stat,
                               .hstat = &dev_random_hstat};

    hdl->info.dev.dev_ops = ops;
    return 0;
}

struct pseudo_fs_ops dev_random_fs_ops = {
    .open = &dev_random_open,
    .mode = &dev_random_mode,
    .stat = &dev_random_stat,
};

/* /dev/urandom is exactly the same as /dev/random, so it has the same operations */
struct pseudo_fs_ops dev_urandom_fs_ops = {
    .open = &dev_random_open,
    .mode = &dev_random_mode,
    .stat = &dev_random_stat,
};
