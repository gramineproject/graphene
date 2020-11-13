/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#include <assert.h>
#include <stdarg.h>
#include <stdint.h>

#include "api.h"
#include "pal.h"
#include "shim_defs.h"
#include "shim_internal.h"
#include "shim_ipc.h"

bool g_debug_log_enabled = false;

static inline int debug_fputs(const char* buf, size_t size) {
    size_t bytes = 0;

    while (bytes < size) {
        PAL_NUM x = DkDebugLog((void*)(buf + bytes), size - bytes);
        if (x == PAL_STREAM_ERROR) {
            int err = PAL_ERRNO();
            if (err == EINTR || err == EAGAIN || err == EWOULDBLOCK) {
                continue;
            }
            return -err;
        }

        bytes += x;
    }

    return 0;
}

static int debug_fputch(void* f, int ch, void* b) {
    __UNUSED(f);
    struct debug_buf* buf = (struct debug_buf*)b;
    buf->buf[buf->end++]  = ch;

    if (ch == '\n') {
        int ret = debug_fputs(buf->buf, buf->end);
        buf->end = buf->start;
        return ret;
    }

#if DEBUGBUF_BREAK == 1
    if (buf->end == DEBUGBUF_SIZE - 4) {
        buf->buf[buf->end++] = '.';
        buf->buf[buf->end++] = '.';
        buf->buf[buf->end++] = '\n';
        debug_fputs(buf->buf, buf->end);
        buf->end             = buf->start;
        buf->buf[buf->end++] = '.';
        buf->buf[buf->end++] = '.';
    }
#else
    if (buf->end == DEBUGBUF_SIZE) {
        debug_fputs(buf->buf, buf->end);
        buf->end = buf->start;
    }
#endif

    return 0;
}

void debug_puts(const char* str) {
    int len               = strlen(str);
    struct debug_buf* buf = shim_get_tcb()->debug_buf;

    while (len) {
        int rem     = DEBUGBUF_SIZE - 4 - buf->end;
        bool isfull = true;

        if (rem > len) {
            rem    = len;
            isfull = false;
        }

        for (int i = 0; i < rem; i++) {
            buf->buf[buf->end + i] = str[i];
        }
        buf->end += rem;
        str += rem;
        len -= rem;

        if (isfull) {
            buf->buf[buf->end++] = '.';
            buf->buf[buf->end++] = '.';
            buf->buf[buf->end++] = '\n';
            debug_fputs(buf->buf, buf->end);
            buf->end             = buf->start;
            buf->buf[buf->end++] = '.';
            buf->buf[buf->end++] = '.';
        }
    }
}

void debug_putch(int ch) {
    debug_fputch(NULL, ch, shim_get_tcb()->debug_buf);
}

void debug_vprintf(const char* fmt, va_list ap) {
    vfprintfmt((void*)debug_fputch, NULL, shim_get_tcb()->debug_buf, fmt, ap);
}

void debug_printf(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    debug_vprintf(fmt, ap);
    va_end(ap);
}

void debug_setprefix(shim_tcb_t* tcb) {
    if (!g_debug_log_enabled)
        return;

    struct debug_buf* buf = tcb->debug_buf;
    buf->start = buf->end = 0;

    const char* exec = PAL_CB(executable);
    for (const char* it = exec; *it; it++)
        if (*it == ':' || *it == '/')
            exec = it + 1;

    uint32_t vmid = g_process_ipc_info.vmid & 0xFFFF;
    if (tcb->tp) {
        if (!is_internal_tid(tcb->tp->tid)) {
            /* normal app thread: show Process ID, Thread ID, and exec name */
            fprintfmt(debug_fputch, NULL, buf, "[P%u:T%u:%s] ", vmid, tcb->tp->tid, exec);
        } else {
            /* internal LibOS thread: show Process ID, Internal-thread ID, and exec name */
            fprintfmt(debug_fputch, NULL, buf, "[P%u:i%u:%s] ", vmid,
                      tcb->tp->tid - INTERNAL_TID_BASE, exec);
        }
    } else if (g_process_ipc_info.vmid) {
        /* unknown thread (happens on process init): show Process ID and exec name */
        fprintfmt(debug_fputch, NULL, buf, "[P%u:%s] ", vmid, exec);
    } else {
        /* unknown process (must never happen): show exec name */
        fprintfmt(debug_fputch, NULL, buf, "[%s] ", exec);
    }

    buf->start = buf->end;
}
