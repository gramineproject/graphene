/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

#include <assert.h>

#include "pal_debug.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "perm.h"
#include "sgx_log.h"

int g_urts_log_level = PAL_LOG_DEFAULT_LEVEL;
int g_urts_log_fd = PAL_LOG_DEFAULT_FD;

int urts_log_init(const char* path) {
    int ret;

    if (g_urts_log_fd != PAL_LOG_DEFAULT_FD) {
        ret = INLINE_SYSCALL(close, 1, g_urts_log_fd);
        g_urts_log_fd = PAL_LOG_DEFAULT_FD;
        if (ret < 0)
            return ret;
    }

    ret = INLINE_SYSCALL(open, 3, path, O_WRONLY | O_APPEND | O_CREAT, PERM_rw_______);
    if (ret < 0)
        return ret;
    g_urts_log_fd = ret;
    return 0;
}
