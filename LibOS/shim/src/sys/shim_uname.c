/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Implementation of system call `uname`.
 */

#include <errno.h>
#include <sys/utsname.h>

#include "api.h"
#include "shim_internal.h"
#include "shim_table.h"

static struct new_utsname graphene_uname = {
    .sysname    = "Linux",
    .nodename   = "localhost",
    .release    = "3.10.0",
    .version    = "1",
    .machine    = "x86_64",
    .domainname = "(none)", /* this seems to be the default on Linux */
};

int shim_do_uname(struct new_utsname* buf) {
    if (!buf || test_user_memory(buf, sizeof(*buf), /*write=*/true))
        return -EFAULT;

    memcpy(buf, &graphene_uname, sizeof(graphene_uname));
    return 0;
}
