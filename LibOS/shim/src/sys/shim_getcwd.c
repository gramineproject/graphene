/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Implementation of system calls "getcwd", "chdir" and "fchdir".
 */

#include <errno.h>

#include "pal.h"
#include "pal_error.h"
#include "shim_fs.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_lock.h"
#include "shim_process.h"
#include "shim_table.h"
#include "shim_thread.h"
#include "shim_utils.h"

#ifndef ERANGE
#define ERANGE 34
#endif

int shim_do_getcwd(char* buf, size_t len) {
    if (!buf || !len)
        return -EINVAL;

    if (test_user_memory(buf, len, true))
        return -EFAULT;

    lock(&g_process.fs_lock);
    struct shim_dentry* cwd = g_process.cwd;
    get_dentry(cwd);
    unlock(&g_process.fs_lock);

    size_t plen = dentry_get_path_size(cwd) - 1;

    int ret;
    if (plen >= MAX_PATH) {
        ret = -ENAMETOOLONG;
    } else if (plen + 1 > len) {
        ret = -ERANGE;
    } else {
        ret = plen + 1;
        dentry_get_path(cwd, buf);
    }

    put_dentry(cwd);
    return ret;
}

int shim_do_chdir(const char* filename) {
    struct shim_dentry* dent = NULL;
    int ret;

    if (!filename)
        return -EINVAL;

    if (test_user_string(filename))
        return -EFAULT;

    if (strnlen(filename, MAX_PATH + 1) == MAX_PATH + 1)
        return -ENAMETOOLONG;

    if ((ret = path_lookupat(NULL, filename, LOOKUP_OPEN, &dent, NULL)) < 0)
        return ret;

    if (!dent)
        return -ENOENT;

    if (!(dent->state & DENTRY_ISDIRECTORY)) {
        char buffer[dentry_get_path_size(dent)];
        debug("%s is not a directory\n", dentry_get_path(dent, buffer));
        put_dentry(dent);
        return -ENOTDIR;
    }

    lock(&g_process.fs_lock);
    put_dentry(g_process.cwd);
    g_process.cwd = dent;
    unlock(&g_process.fs_lock);
    return 0;
}

int shim_do_fchdir(int fd) {
    struct shim_thread* thread = get_cur_thread();
    struct shim_handle* hdl    = get_fd_handle(fd, NULL, thread->handle_map);
    if (!hdl)
        return -EBADF;

    struct shim_dentry* dent = hdl->dentry;

    if (!(dent->state & DENTRY_ISDIRECTORY)) {
        char buffer[dentry_get_path_size(dent)];
        debug("%s is not a directory\n", dentry_get_path(dent, buffer));
        put_handle(hdl);
        return -ENOTDIR;
    }

    lock(&g_process.fs_lock);
    get_dentry(dent);
    put_dentry(g_process.cwd);
    g_process.cwd = dent;
    unlock(&g_process.fs_lock);
    put_handle(hdl);
    return 0;
}
