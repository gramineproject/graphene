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
 * shim_getcwd.c
 *
 * Implementation of system call "getcwd", "chdir" and "fchdir".
 */

#include <errno.h>
#include <pal.h>
#include <pal_error.h>
#include <shim_fs.h>
#include <shim_handle.h>
#include <shim_internal.h>
#include <shim_table.h>
#include <shim_thread.h>
#include <shim_utils.h>

#ifndef ERANGE
#define ERANGE 34
#endif

int shim_do_getcwd(char* buf, size_t len) {
    if (!buf || !len)
        return -EINVAL;

    if (test_user_memory(buf, len, true))
        return -EFAULT;

    struct shim_thread* thread = get_cur_thread();
    assert(thread);

    struct shim_dentry* cwd = thread->cwd;

    size_t plen;
    const char* path = dentry_get_path(cwd, true, &plen);

    int ret;
    if (plen >= MAX_PATH) {
        ret = -ENAMETOOLONG;
    } else if (plen + 1 > len) {
        ret = -ERANGE;
    } else {
        ret = plen + 1;
        memcpy(buf, path, plen + 1);
    }
    return ret;
}

int shim_do_chdir(const char* filename) {
    struct shim_thread* thread = get_cur_thread();
    assert(thread);
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
        debug("%s is not a directory\n", dentry_get_path(dent, false, NULL));
        put_dentry(dent);
        return -ENOTDIR;
    }

    lock(&thread->lock);
    put_dentry(thread->cwd);
    thread->cwd = dent;
    unlock(&thread->lock);
    return 0;
}

int shim_do_fchdir(int fd) {
    struct shim_thread* thread = get_cur_thread();
    struct shim_handle* hdl    = get_fd_handle(fd, NULL, thread->handle_map);
    if (!hdl)
        return -EBADF;

    struct shim_dentry* dent = hdl->dentry;

    if (!(dent->state & DENTRY_ISDIRECTORY)) {
        debug("%s is not a directory\n", dentry_get_path(dent, false, NULL));
        put_handle(hdl);
        return -ENOTDIR;
    }

    lock(&thread->lock);
    get_dentry(dent);
    put_dentry(thread->cwd);
    thread->cwd = dent;
    unlock(&thread->lock);
    put_handle(hdl);
    return 0;
}
