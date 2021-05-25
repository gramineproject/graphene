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

extern int g_urts_log_level;
extern int g_urts_log_fd;

int urts_log_init(const char* path);
int urts_log_printf(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

// TODO(mkow): We should make it cross-object-inlinable, ideally by enabling LTO, less ideally by
// pasting it here and making `inline`, but our current linker scripts prevent both.
void pal_log(int level, const char* fmt, ...) __attribute__((format(printf, 2, 3)));

/* NOTE: these macros are identical to log_error, log_warning, etc. but defined for readability */
#define urts_log_always(fmt...)   pal_log(LOG_LEVEL_NONE, fmt)
#define urts_log_error(fmt...)    pal_log(LOG_LEVEL_ERROR, fmt)
#define urts_log_warning(fmt...)  pal_log(LOG_LEVEL_WARNING, fmt)
#define urts_log_debug(fmt...)    pal_log(LOG_LEVEL_DEBUG, fmt)
#define urts_log_trace(fmt...)    pal_log(LOG_LEVEL_TRACE, fmt)

#endif /* SGX_LOG_H_ */
