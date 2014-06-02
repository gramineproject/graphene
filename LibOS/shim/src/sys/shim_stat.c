/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2014 OSCAR lab, Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * shim_stat.c
 *
 * Implementation of system call "stat", "lstat", "fstat" and "readlink".
 */

#include <shim_internal.h>
#include <shim_table.h>
#include <shim_handle.h>
#include <shim_fs.h>
#include <shim_profile.h>

#include <pal.h>
#include <pal_error.h>

#include <errno.h>

int shim_do_stat (const char * file, struct stat * stat)
{
    if (!file)
        return -EFAULT;

    int ret;
    struct shim_dentry * dent = NULL;

    if ((ret = path_lookupat(NULL, file, LOOKUP_ACCESS, &dent)) < 0)
        goto out;

    struct shim_mount * fs = dent->fs;

    if (!fs->d_ops || !fs->d_ops->stat) {
        ret = -EACCES;
        goto out_dentry;
    }

    ret = fs->d_ops->stat(dent, stat);
out_dentry:
    put_dentry(dent);
out:
    return ret;
}

int shim_do_lstat (const char * file, struct stat * stat)
{
    if (!file)
        return -EFAULT;

    int ret;
    struct shim_dentry * dent = NULL;

    if ((ret = path_lookupat(NULL, file, LOOKUP_ACCESS, &dent)) < 0)
        goto out;

    struct shim_mount * fs = dent->fs;

    if (!fs->d_ops || !fs->d_ops->stat) {
        ret = -EACCES;
        goto out_dentry;
    }

    ret = fs->d_ops->stat(dent, stat);
out_dentry:
    put_dentry(dent);
out:
    return ret;
}

int shim_do_fstat (int fd, struct stat * stat)
{
    struct shim_handle * hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    int ret = -EACCES;
    struct shim_mount * fs = hdl->fs;

    if (!fs || !fs->fs_ops)
        goto out;

    if (!fs->fs_ops->hstat)
        goto out;

    ret = fs->fs_ops->hstat(hdl, stat);
out:
    put_handle(hdl);
    return ret;
}

int shim_do_readlink (const char * file, char * buf, int bufsize)
{
    if (!file)
        return -EFAULT;

    if (bufsize <= 0)
        return -EINVAL;

    int ret;
    struct shim_dentry * dent = NULL;

    if ((ret = path_lookupat(NULL, file, LOOKUP_ACCESS, &dent)) < 0)
        return ret;

    char * relpath;
    int len;

    relpath = dentry_get_path(dent, true, &len);
    if (len > bufsize)
        len = bufsize;
    memcpy(buf, relpath, len);
    put_dentry(dent);
    return len;
}
