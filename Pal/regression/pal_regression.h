/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation */

#ifndef PAL_REGRESSION_H
#define PAL_REGRESSION_H

#include <stdarg.h>

#include "api.h"
#include "pal.h"

#define pal_control (*DkGetPalControl())

static inline int buf_write_all(const char* str, size_t size, void* arg) {
    __UNUSED(arg);
    DkDebugLog((PAL_PTR)str, size);
    return 0;
}

static inline void log_vprintf(const char* fmt, va_list ap) {
    struct print_buf buf = INIT_PRINT_BUF(buf_write_all);
    buf_vprintf(&buf, fmt, ap);
    buf_flush(&buf);
}

static inline void __attribute__((format(printf, 1, 2))) pal_printf(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    log_vprintf(fmt, ap);
    va_end(ap);
}

#endif /* PAL_REGRESSION_H */
