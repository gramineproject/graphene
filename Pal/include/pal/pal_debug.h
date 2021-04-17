/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains definitions of APIs used for debug purposes.
 */

#ifndef PAL_DEBUG_H
#define PAL_DEBUG_H

#include <stdarg.h>

#include "pal.h"

// TODO: Replace this with log_* everywhere
void pal_printf(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
void pal_vprintf(const char* fmt, va_list ap) __attribute__((format(printf, 1, 0)));

void warn(const char* format, ...);

void DkDebugMapAdd(PAL_STR uri, PAL_PTR start_addr);
void DkDebugMapRemove(PAL_PTR start_addr);

#endif /* PAL_DEBUG_H */
