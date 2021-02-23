/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#include <errno.h>
#include <linux/futex.h>

#include "atomic.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_error.h"
#include "sgx_internal.h"
#include "sgx_log.h"

#define PRINTBUF_SIZE 256

struct printbuf {
    int idx; // current buffer index
    int cnt; // total bytes printed so far
    char buf[PRINTBUF_SIZE];
};

static int fputch(void* f, int ch, void* _buf) {
    __UNUSED(f);

    struct printbuf* buf = (struct printbuf*)_buf;

    buf->buf[buf->idx++] = ch;
    if (buf->idx == PRINTBUF_SIZE - 1) {
        INLINE_SYSCALL(write, 3, 2, buf->buf, buf->idx);
        buf->idx = 0;
    }
    buf->cnt++;
    return 0;
}

static int vfdprintf(int fd, const char* fmt, va_list ap) {
    struct printbuf buf;

    buf.idx = 0;
    buf.cnt = 0;
    vfprintfmt(fputch, NULL, &buf, fmt, ap);
    INLINE_SYSCALL(write, 3, fd, buf.buf, buf.idx);

    return buf.cnt;
}

int pal_printf(const char* fmt, ...) {
    va_list ap;
    int cnt;

    va_start(ap, fmt);
    cnt = vfdprintf(2, fmt, ap);
    va_end(ap);

    return cnt;
}

void _urts_log(int level, const char* fmt, ...) {
    if (level <= g_urts_log_level) {
        va_list ap;
        va_start(ap, fmt);
        vfdprintf(g_urts_log_fd, fmt, ap);
        va_end(ap);
    }
}
