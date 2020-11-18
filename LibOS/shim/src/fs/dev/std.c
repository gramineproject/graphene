/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Labs */

/*!
 * \file
 *
 * This file contains the implementation of `/dev/stdin`, `/dev/stdout`, `/dev/stderr` pseudo-files.
 */

#include "shim_fs.h"
#include "stat.h"

static int dev_std_mode(const char* name, mode_t* mode) {
    __UNUSED(name);
    *mode = FILE_RW_MODE | S_IFCHR;
    return 0;
}

static int dev_std_stat(const char* name, struct stat* buf) {
    __UNUSED(name);
    memset(buf, 0, sizeof(*buf));

    buf->st_mode = FILE_RW_MODE | S_IFLNK;
    return 0;
}

static int dev_std_open(struct shim_handle* hdl, const char* name, int flags) {
    __UNUSED(hdl);
    __UNUSED(name);
    __UNUSED(flags);
    return 0;
}

static int dev_stdin_follow_link(const char* name, struct shim_qstr* link) {
    __UNUSED(name);
    qstrsetstr(link, "/proc/self/fd/0", static_strlen("/proc/self/fd/0"));
    return 0;
}

static int dev_stdout_follow_link(const char* name, struct shim_qstr* link) {
    __UNUSED(name);
    qstrsetstr(link, "/proc/self/fd/1", static_strlen("/proc/self/fd/1"));
    return 0;
}

static int dev_stderr_follow_link(const char* name, struct shim_qstr* link) {
    __UNUSED(name);
    qstrsetstr(link, "/proc/self/fd/2", static_strlen("/proc/self/fd/2"));
    return 0;
}

struct pseudo_fs_ops dev_stdin_fs_ops = {
    .open        = &dev_std_open,
    .mode        = &dev_std_mode,
    .stat        = &dev_std_stat,
    .follow_link = &dev_stdin_follow_link,
};

struct pseudo_fs_ops dev_stdout_fs_ops = {
    .open        = &dev_std_open,
    .mode        = &dev_std_mode,
    .stat        = &dev_std_stat,
    .follow_link = &dev_stdout_follow_link,
};

struct pseudo_fs_ops dev_stderr_fs_ops = {
    .open        = &dev_std_open,
    .mode        = &dev_std_mode,
    .stat        = &dev_std_stat,
    .follow_link = &dev_stderr_follow_link,
};
