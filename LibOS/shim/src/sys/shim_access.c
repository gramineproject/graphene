/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

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

#include <shim_internal.h>
#include <shim_table.h>
#include <shim_thread.h>
#include <shim_handle.h>
#include <shim_fs.h>

#include <pal.h>
#include <pal_error.h>

#include <linux/fcntl.h>
#include <errno.h>

int shim_do_access (const char * file, mode_t mode)
{
    if (!file)
        return -EINVAL;

    if (test_user_string(file))
        return -EFAULT;

    struct shim_dentry * dent = NULL;
    int ret = 0;

    ret = path_lookupat(NULL, file, LOOKUP_ACCESS|LOOKUP_FOLLOW, &dent, NULL);
    if (!ret)
        ret = permission(dent, mode, 1);

    return ret;
}

int shim_do_faccessat (int dfd, const char * filename, mode_t mode)
{
    if (!filename)
        return -EINVAL;

    if (test_user_string(filename))
        return -EFAULT;

    if (*filename == '/')
        return shim_do_access(filename, mode);

    struct shim_dentry * dir = NULL, * dent = NULL;
    int ret = 0;

    if ((ret = path_startat(dfd, &dir)) < 0)
        return ret;

    ret = path_lookupat(dir, filename, LOOKUP_ACCESS|LOOKUP_FOLLOW, &dent, NULL);
    if (ret < 0)
        goto out;

    ret = permission(dent, mode, 1);

out:
    put_dentry(dir);
    return ret;
}
