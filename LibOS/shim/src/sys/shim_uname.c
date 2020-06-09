/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

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
