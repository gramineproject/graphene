/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Invisible Things Lab
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

/*
 * Implementation of system calls `uname`, `sethostname` and `setdomainname`.
 */

#include <errno.h>
#include <sys/utsname.h>

#include "api.h"
#include "shim_internal.h"
#include "shim_table.h"

/* This structure is *not* shared between Graphene processes, despite it should. As a result,
 * effects of set{host,domain}name in process A will not be visible in process B.
 * These syscalls are rarely used and are implemented in Graphene mainly to enable LTP to test
 * our `uname` implementation. */
static struct new_utsname g_current_uname = {
    .sysname  = "Linux",
    .nodename = "localhost",
    .release  = "3.10.0",
    .version  = "1",
#ifdef __x86_64__
    .machine  = "x86_64",
#else
#error "Not implemented"
#endif
    .domainname = "(none)", /* this seems to be the default on Linux */
};

long shim_do_uname(struct new_utsname* buf) {
    if (test_user_memory(buf, sizeof(*buf), /*write=*/true))
        return -EFAULT;

    memcpy(buf, &g_current_uname, sizeof(g_current_uname));
    return 0;
}

long shim_do_sethostname(char* name, int len) {
    if (len < 0 || (size_t)len >= sizeof(g_current_uname.nodename))
        return -EINVAL;

    if (test_user_memory(name, len, /*write=*/false))
        return -EFAULT;

    memcpy(&g_current_uname.nodename, name, len);
    memset(&g_current_uname.nodename[len], 0, sizeof(g_current_uname.nodename) - len);
    return 0;
}

long shim_do_setdomainname(char* name, int len) {
    if (len < 0 || (size_t)len >= sizeof(g_current_uname.domainname))
        return -EINVAL;

    if (test_user_memory(name, len, /*write=*/false))
        return -EFAULT;

    memcpy(&g_current_uname.domainname, name, len);
    memset(&g_current_uname.domainname[len], 0, sizeof(g_current_uname.domainname) - len);
    return 0;
}
