/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * Outer PAL logging interface. This is initialized separately to inner PAL, but (once it's
 * initialized) should output at the level and to the file specified in manifest.
 */

#ifndef SGX_LOG_H_
#define SGX_LOG_H_

#include "pal.h"
#include "pal_debug.h"

extern int g_sgx_log_level;
extern int g_sgx_log_fd;

int sgx_log_init(const char* path);
int sgx_log_printf(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

#define _sgx_log(level, fmt...)                          \
    do {                                                 \
        if ((level) <= g_sgx_log_level)                  \
            pal_fdprintf(g_sgx_log_fd, fmt);             \
    }  while(0)

#define sgx_log_error(fmt...)    _sgx_log(PAL_LOG_ERROR, fmt)
#define sgx_log_info(fmt...)     _sgx_log(PAL_LOG_INFO, fmt)
#define sgx_log_debug(fmt...)    _sgx_log(PAL_LOG_DEBUG, fmt)
#define sgx_log_trace(fmt...)    _sgx_log(PAL_LOG_TRACE, fmt)

#endif /* SGX_LOG_H_ */
