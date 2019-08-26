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
 * shim_uname.c
 *
 * Implementation of system call "uname".
 */

#include <errno.h>
#include <shim_fs.h>
#include <shim_handle.h>
#include <shim_internal.h>
#include <shim_table.h>
#include <shim_utils.h>
#include <sys/utsname.h>

/* DP: Damned lies */
static struct old_utsname graphene_uname = {.sysname  = "Linux",
                                            .nodename = "localhost",
                                            .release  = "3.10.0",
                                            .version  = "1",
                                            .machine  = "x86_64"};

int shim_do_uname(struct old_utsname* buf) {
    if (!buf || test_user_memory(buf, sizeof(*buf), true))
        return -EFAULT;

    memcpy(buf, &graphene_uname, sizeof(graphene_uname));
    return 0;
}
