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
 * shim_access.c
 *
 * Implementation of system call "access" and "faccessat".
 */

#include <errno.h>
#include <linux/fcntl.h>

#include <pal.h>
#include <pal_error.h>
#include <shim_fs.h>
#include <shim_handle.h>
#include <shim_internal.h>
#include <shim_table.h>
#include <shim_thread.h>

int shim_do_access(const char* file, mode_t mode) {
    if (!file)
        return -EINVAL;

    if (test_user_string(file))
        return -EFAULT;

    struct shim_dentry* dent = NULL;
    int ret = 0;

    lock(&dcache_lock);

    ret = __path_lookupat(NULL, file, LOOKUP_ACCESS | LOOKUP_FOLLOW, &dent, 0, NULL, false);
    if (!ret)
        ret = __permission(dent, mode);

    unlock(&dcache_lock);

    return ret;
}

int shim_do_faccessat(int dfd, const char* filename, mode_t mode) {
    if (!filename)
        return -EINVAL;

    if (test_user_string(filename))
        return -EFAULT;

    struct shim_dentry* dir = NULL;
    struct shim_dentry* dent = NULL;
    int ret = 0;

    if ((ret = get_dirfd_dentry(dfd, &dir)) < 0)
        return ret;

    lock(&dcache_lock);

    ret = __path_lookupat(dir, filename, LOOKUP_ACCESS | LOOKUP_FOLLOW, &dent, 0, NULL, false);
    if (ret < 0)
        goto out;

    ret = __permission(dent, mode);

out:
    unlock(&dcache_lock);

    put_dentry(dir);
    return ret;
}
