/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#include "api.h"
#include "assert.h"
#include "pal_internal.h"

// Collect up to PRINTBUF_SIZE characters into a buffer
// and perform ONE system call to print all of them,
// in order to make the lines output to the console atomic
// and prevent interrupts from causing context switches
// in the middle of a console output line and such.

#define PRINTBUF_SIZE 256

static const char* log_level_to_prefix[] = {
    [PAL_LOG_NONE]    = "", // not a valid entry actually (no public wrapper uses this log level)
    [PAL_LOG_ERROR]   = "error: ",
    [PAL_LOG_WARNING] = "warning: ",
    [PAL_LOG_DEBUG]   = "debug: ",
    [PAL_LOG_TRACE]   = "trace: ",
    [PAL_LOG_ALL]     = "", // same as for PAL_LOG_NONE
};

struct printbuf {
    size_t idx;  // current buffer index
    size_t cnt;  // total bytes printed so far
    char buf[PRINTBUF_SIZE];
};

static int fputch(void* f, int ch, void* buf_) {
    __UNUSED(f);
    struct printbuf* buf = buf_;

    buf->buf[buf->idx++] = ch;
    if (buf->idx == PRINTBUF_SIZE - 1) {
        _DkPrintConsole(buf->buf, buf->idx);
        buf->idx = 0;
    }
    buf->cnt++;
    return 0;
}

// TODO: Remove this and always use log_*.
__attribute__((format(printf, 1, 0)))
int vprintf(const char* fmt, va_list ap) {
    struct printbuf buf;

    buf.idx = 0;
    buf.cnt = 0;
    vfprintfmt(fputch, NULL, &buf, fmt, ap);
    _DkPrintConsole(buf.buf, buf.idx);

    return buf.cnt;
}

static void log_vprintf(const char* fmt, va_list ap) {
    struct printbuf buf;

    buf.idx = 0;
    buf.cnt = 0;
    vfprintfmt(fputch, NULL, &buf, fmt, ap);
    _DkDebugLog(buf.buf, buf.idx);
}

// TODO: Make this static and always use log_* outside of this file.
int printf(const char* fmt, ...) {
    va_list ap;
    int cnt;

    va_start(ap, fmt);
    cnt = vprintf(fmt, ap);
    va_end(ap);

    return cnt;
}
EXTERN_ALIAS(printf);

void _log(int level, const char* fmt, ...) {
    if (level <= g_pal_control.log_level) {
        va_list ap;
        va_start(ap, fmt);
        assert(0 <= level && (size_t)level < ARRAY_SIZE(log_level_to_prefix));
        log_always("%s", log_level_to_prefix[level]);
        log_vprintf(fmt, ap);
        va_end(ap);
    }
}

void log_always(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    log_vprintf(fmt, ap);
    va_end(ap);
}
