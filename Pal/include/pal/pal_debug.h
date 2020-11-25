/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains definitions of APIs used for debug purposes.
 */

#ifndef PAL_DEBUG_H
#define PAL_DEBUG_H

#include "pal.h"

int pal_printf(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
int pal_fdprintf(int fd, const char* fmt, ...) __attribute__((format(printf, 2, 3)));
void warn(const char* format, ...);

void DkDebugAttachBinary(PAL_STR uri, PAL_PTR start_addr);
void DkDebugDetachBinary(PAL_PTR start_addr);

#endif /* PAL_DEBUG_H */
