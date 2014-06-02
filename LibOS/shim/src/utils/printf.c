/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2014 OSCAR lab, Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include <shim_defs.h>
#include <shim_internal.h>
#include <shim_ipc.h>

#include <pal.h>
#include <api.h>

#include <stdint.h>
#include <stdarg.h>

PAL_HANDLE debug_handle = NULL;

struct debugbuf {
    int cnt;
    char buf[DEBUGBUF_SIZE];
};

static inline void
debug_fputs (void * f, const char * buf, int len)
{
    DkStreamWrite(debug_handle, 0, len, buf, NULL);
}

static void
debug_fputch (void * f, int ch, void * b)
{
    struct debug_buf * buf = (struct debug_buf *) b;
    buf->buf[buf->end++] = ch;

    if (ch == '\n') {
        debug_fputs(NULL, buf->buf, buf->end);
        buf->end = buf->start;
        return;
    }

    if (buf->end == DEBUGBUF_SIZE - 4) {
        buf->buf[buf->end++] = '.';
        buf->buf[buf->end++] = '.';
        buf->buf[buf->end++] = '\n';
        debug_fputs(NULL, buf->buf, buf->end);
        buf->end = buf->start;
        buf->buf[buf->end++] = '.';
        buf->buf[buf->end++] = '.';
    }
}

void debug_puts (const char * str)
{
    int len = strlen(str);
    struct debug_buf * buf = (struct debug_buf *) SHIM_GET_TLS()->debug_buf;

    while (len) {
        int rem = DEBUGBUF_SIZE - 4 - buf->end;
        bool isfull = true;

        if (rem > len) {
            rem = len;
            isfull = false;
        }

        for (int i = 0 ; i < rem ; i++)
            buf->buf[buf->end + i] = str[i];
        buf->end += rem;
        str += rem;
        len -= rem;

        if (isfull) {
            buf->buf[buf->end++] = '.';
            buf->buf[buf->end++] = '.';
            buf->buf[buf->end++] = '\n';
            debug_fputs(NULL, buf->buf, buf->end);
            buf->end = buf->start;
            buf->buf[buf->end++] = '.';
            buf->buf[buf->end++] = '.';
        }
    }
}

void debug_putch (int ch)
{
    debug_fputch(NULL, ch, SHIM_GET_TLS()->debug_buf);
}

void debug_vprintf (const char * fmt, va_list ap)
{
    vfprintfmt((void *) debug_fputch, NULL, SHIM_GET_TLS()->debug_buf,
               fmt, ap);
}

void debug_printf (const char * fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    debug_vprintf(fmt, ap);
    va_end(ap);
}

void debug_setprefix (shim_tcb_t * tcb)
{
    if (!debug_handle)
        return;

    struct debug_buf * buf = (struct debug_buf *) tcb->debug_buf;
    buf->start = buf->end = 0;

    if (tcb->tid && !IS_INTERNAL_TID(tcb->tid))
        fprintfmt(debug_fputch, NULL, buf, TID_PREFIX, tcb->tid);
    else if (cur_process.vmid)
        fprintfmt(debug_fputch, NULL, buf, VMID_PREFIX,
                  cur_process.vmid % 10000);
    else
        fprintfmt(debug_fputch, NULL, buf, NOID_PREFIX);

    buf->start = buf->end;
}

struct sysbuf {
    int cnt;
    char buf[SYSPRINT_BUFFER_SIZE];
} sys_putdat;

static inline void
sys_fputs (void * f, const char * str, int len)
{
    DkStreamWrite((PAL_HANDLE) f, 0, len, str, NULL);
}

static void
sys_fputch (void * f, int ch, void * b)
{
    sys_putdat.buf[sys_putdat.cnt++] = ch;

    if (ch == '\n') {
        sys_fputs(f, sys_putdat.buf, sys_putdat.cnt);
        sys_putdat.cnt = 0;
    }

    if (sys_putdat.cnt == SYSPRINT_BUFFER_SIZE - 2) {
        sys_putdat.buf[sys_putdat.cnt++] = '\n';
        sys_fputs(f, sys_putdat.buf, sys_putdat.cnt);
        sys_putdat.cnt = 0;
    }
}

static void
sys_vfprintf (PAL_HANDLE hdl, const char * fmt, va_list ap)
{
    vfprintfmt((void *) &sys_fputch, hdl, NULL, fmt, ap);
}

void handle_printf (PAL_HANDLE hdl, const char * fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    sys_vfprintf(hdl, fmt, ap);
    va_end(ap);
}

struct sprintbuf {
    char *buf;
    char *ebuf;
    int cnt;
};

static void
sprintputch(void * f, int ch, struct sprintbuf * b)
{
    b->cnt++;
    if (b->buf < b->ebuf)
        *b->buf++ = ch;
}

int snprintfmt(char * buf, size_t n, const char * fmt, va_list ap)
{
    struct sprintbuf b = {buf, buf + n - 1, 0};

    if (buf == NULL || n < 1)
        return -1;

    vfprintfmt((void *) sprintputch, NULL, &b, fmt, ap);
    // null terminate the buffer
    *b.buf = '\0';

    return b.cnt;
}

int
snprintf(char * buf, size_t n, const char * fmt, ...)
{
    va_list ap;
    struct sprintbuf b = {buf, buf + n - 1, 0};

    if (buf == NULL || n < 1)
        return -1;

    va_start(ap, fmt);

    // print the string to the buffer
    vfprintfmt((void *) sprintputch, NULL, &b, fmt, ap);
    // null terminate the buffer
    *b.buf = '\0';

    va_end(ap);

    return b.cnt;
}
