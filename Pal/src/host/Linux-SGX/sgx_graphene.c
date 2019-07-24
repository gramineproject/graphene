/* Copyright (C) 2014 Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include <pal.h>
#include <pal_error.h>
#include <atomic.h>

#include <linux/futex.h>
#include <errno.h>

#include "sgx_internal.h"

#define PRINTBUF_SIZE        256

struct printbuf {
    int idx;    // current buffer index
    int cnt;    // total bytes printed so far
    char buf[PRINTBUF_SIZE];
};

static int
fputch(void * f, int ch, struct printbuf * b)
{
    __UNUSED(f);

    b->buf[b->idx++] = ch;
    if (b->idx == PRINTBUF_SIZE - 1) {
        INLINE_SYSCALL(write, 3, 2, b->buf, b->idx);
        b->idx = 0;
    }
    b->cnt++;
    return 0;
}

static int
vprintf(const char * fmt, va_list ap)
{
    struct printbuf b;

    b.idx = 0;
    b.cnt = 0;
    vfprintfmt((void *) &fputch, NULL, &b, fmt, ap);
    INLINE_SYSCALL(write, 3, 2, b.buf, b.idx);

    return b.cnt;
}

int
pal_printf(const char * fmt, ...)
{
    va_list ap;
    int cnt;

    va_start(ap, fmt);
    cnt = vprintf(fmt, ap);
    va_end(ap);

    return cnt;
}
