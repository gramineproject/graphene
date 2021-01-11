/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#include "api.h"
#include "pal_internal.h"

#ifndef NO_INTERNAL_PRINTF

// Collect up to PRINTBUF_SIZE characters into a buffer
// and perform ONE system call to print all of them,
// in order to make the lines output to the console atomic
// and prevent interrupts from causing context switches
// in the middle of a console output line and such.

#define PRINTBUF_SIZE 256

struct printbuf {
    int idx;  // current buffer index
    int cnt;  // total bytes printed so far
    char buf[PRINTBUF_SIZE];
};

static int fputch(void* f, int ch, void* putdat) {
    __UNUSED(f);
    struct printbuf* b = putdat;

    b->buf[b->idx++] = ch;
    if (b->idx == PRINTBUF_SIZE - 1) {
        _DkPrintConsole(b->buf, b->idx);
        b->idx = 0;
    }
    b->cnt++;
    return 0;
}

int vprintf(const char* fmt, va_list ap) {
    struct printbuf b;

    b.idx = 0;
    b.cnt = 0;
    vfprintfmt(&fputch, NULL, &b, fmt, ap);
    _DkPrintConsole(b.buf, b.idx);

    return b.cnt;
}

int log_vprintf(const char* fmt, va_list ap) {
    struct printbuf b;

    b.idx = 0;
    b.cnt = 0;
    vfprintfmt(&fputch, NULL, &b, fmt, ap);
    _DkDebugLog(b.buf, b.idx);

    return b.cnt;
}

int printf(const char* fmt, ...) {
    va_list ap;
    int cnt;

    va_start(ap, fmt);
    cnt = vprintf(fmt, ap);
    va_end(ap);

    return cnt;
}
EXTERN_ALIAS(printf);

int log_printf(const char* fmt, ...) {
    va_list ap;
    int cnt;

    va_start(ap, fmt);
    cnt = log_vprintf(fmt, ap);
    va_end(ap);

    return cnt;
}
#endif
