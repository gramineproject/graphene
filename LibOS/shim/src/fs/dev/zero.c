/* Copyright (C) 2020 Intel Labs
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
 * This file contains the implementation of `/dev/zero` pseudo-file.
 */

#include "shim_fs.h"

static ssize_t dev_zero_read(struct shim_handle* hdl, void* buf, size_t count) {
    __UNUSED(hdl);
    memset(buf, 0, count);
    return count;
}

static ssize_t dev_zero_write(struct shim_handle* hdl, const void* buf, size_t count) {
    __UNUSED(hdl);
    __UNUSED(buf);
    __UNUSED(count);
    return count;
}

static int dev_zero_truncate(struct shim_handle* hdl, uint64_t size) {
    __UNUSED(hdl);
    __UNUSED(size);
    return 0;
}

static int dev_zero_mode(const char* name, mode_t* mode) {
    __UNUSED(name);
    *mode = FILE_RW_MODE | S_IFCHR;
    return 0;
}

static int dev_zero_stat(const char* name, struct stat* buf) {
    __UNUSED(name);
    memset(buf, 0, sizeof(*buf));

    buf->st_mode = FILE_RW_MODE | S_IFCHR;
    return 0;
}

static int dev_zero_hstat(struct shim_handle* hdl, struct stat* buf) {
    __UNUSED(hdl);
    return dev_zero_stat(/*name=*/NULL, buf);
}

static int dev_zero_open(struct shim_handle* hdl, const char* name, int flags) {
    __UNUSED(name);
    __UNUSED(flags);

    struct shim_dev_ops ops = {.read     = &dev_zero_read,
                               .write    = &dev_zero_write,
                               .truncate = &dev_zero_truncate,
                               .mode     = &dev_zero_mode,
                               .stat     = &dev_zero_stat,
                               .hstat    = &dev_zero_hstat};

    memcpy(&hdl->info.dev.dev_ops, &ops, sizeof(ops));
    return 0;
}

struct pseudo_fs_ops dev_zero_fs_ops = {
    .open = &dev_zero_open,
    .mode = &dev_zero_mode,
    .stat = &dev_zero_stat,
};
