/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#include "api.h"
#include "assert.h"
#include "pal_debug.h"
#include "pal_internal.h"

static const char* log_level_to_prefix[] = {
    [PAL_LOG_NONE]    = "", // not a valid entry actually (no public wrapper uses this log level)
    [PAL_LOG_ERROR]   = "error: ",
    [PAL_LOG_WARNING] = "warning: ",
    [PAL_LOG_DEBUG]   = "debug: ",
    [PAL_LOG_TRACE]   = "trace: ",
    [PAL_LOG_ALL]     = "", // same as for PAL_LOG_NONE
};

static int buf_write_all(const char* str, size_t size, void* arg) {
    __UNUSED(arg);
    _DkDebugLog(str, size);
    return 0;
}

static void log_vprintf(const char* prefix, const char* fmt, va_list ap) {
    struct print_buf buf = INIT_PRINT_BUF(buf_write_all);

    if (prefix)
        buf_puts(&buf, prefix);
    buf_vprintf(&buf, fmt, ap);
    buf_flush(&buf);
}

// TODO: Replace this with log_* everywhere
void pal_printf(const char* fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    log_vprintf(/*prefix=*/NULL, fmt, ap);
    va_end(ap);
}

// TODO: Replace this with log_* everywhere
void pal_vprintf(const char* fmt, va_list ap) {
    return log_vprintf(/*prefix=*/NULL, fmt, ap);
}

void _log(int level, const char* fmt, ...) {
    if (level <= g_pal_control.log_level) {
        va_list ap;
        va_start(ap, fmt);
        assert(0 <= level && (size_t)level < ARRAY_SIZE(log_level_to_prefix));
        log_vprintf(log_level_to_prefix[level], fmt, ap);
        va_end(ap);
    }
}

void log_always(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    log_vprintf(/*prefix=*/NULL, fmt, ap);
    va_end(ap);
}
