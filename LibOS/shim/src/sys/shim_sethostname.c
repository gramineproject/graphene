/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Invisible Things Lab
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

/*
 * Implementation of system call `sethostname`.
 */

#include <errno.h>

#include "api.h"
#include "shim_internal.h"
#include "shim_table.h"

long shim_do_sethostname(char* name, int len) {
    if (len < 0 || (size_t)len >= sizeof(g_current_uname.nodename))
        return -EINVAL;

    if (test_user_memory(name, len, /*write=*/false))
        return -EFAULT;

    memcpy(&g_current_uname.nodename, name, len);
    memset(&g_current_uname.nodename + len, 0, sizeof(g_current_uname.nodename) - len);
    return 0;
}
