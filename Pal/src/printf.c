/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#include "api.h"
#include "assert.h"
#include "pal.h"
#include "pal_internal.h"

/*
 * NOTE: The logging subsystem cannot be used during early PAL startup, because the pointers in the
 * `log_level_to_prefix` array need to be relocated first. If that becomes an issue (that is, if we
 * want to use logging before or during relocation), this array can be converted to a switch.
 */

/* NOTE: We could add "pal" prefix to the below strings for more fine-grained log info */
static const char* log_level_to_prefix[] = {
    [LOG_LEVEL_NONE]    = "",
    [LOG_LEVEL_ERROR]   = "error: ",
    [LOG_LEVEL_WARNING] = "warning: ",
    [LOG_LEVEL_DEBUG]   = "debug: ",
    [LOG_LEVEL_TRACE]   = "trace: ",
    [LOG_LEVEL_ALL]     = "", // not a valid entry actually (no public wrapper uses this log level)
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
    buf_printf(&buf, "\n");
    buf_flush(&buf);
}

void pal_log(int level, const char* fmt, ...) {
    if (level <= g_pal_control.log_level) {
        va_list ap;
        va_start(ap, fmt);
        assert(0 <= level && (size_t)level < ARRAY_SIZE(log_level_to_prefix));
        log_vprintf(log_level_to_prefix[level], fmt, ap);
        va_end(ap);
    }
}
