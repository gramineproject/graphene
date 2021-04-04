/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */
/* Copyright (C) 2021 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

#include <stdarg.h>
#include <stdint.h>

#include "api.h"
#include "assert.h"
#include "pal.h"
#include "shim_defs.h"
#include "shim_internal.h"
#include "shim_ipc.h"

int g_log_level = PAL_LOG_NONE;

static const char* log_level_to_prefix[] = {
    [PAL_LOG_NONE]    = "", // not a valid entry actually (no public wrapper uses this log level)
    [PAL_LOG_ERROR]   = "error: ",
    [PAL_LOG_WARNING] = "warning: ",
    [PAL_LOG_DEBUG]   = "debug: ",
    [PAL_LOG_TRACE]   = "trace: ",
    [PAL_LOG_ALL]     = "", // same as for PAL_LOG_NONE
};

static int log_one_char(void* f, int ch, void* buf_) {
    __UNUSED(f);
    int ret = 0;
    struct log_buf* buf = (struct log_buf*)buf_;

    buf->buf[buf->end++] = ch;

    if (ch == '\n' || buf->end == LOG_BUF_SIZE) {
        ret = DkDebugLog((void*)buf->buf, buf->end);
        if (ret < 0)
            ret = pal_to_unix_errno(ret);
        buf->end = buf->start;
    }

    return ret;
}

void log_setprefix(shim_tcb_t* tcb) {
    if (g_log_level <= PAL_LOG_NONE)
        return;

    struct log_buf* buf = tcb->log_buf;
    buf->start = buf->end = 0;

    const char* exec = PAL_CB(executable);
    for (const char* it = exec; *it; it++)
        if (*it == ':' || *it == '/')
            exec = it + 1;

    uint32_t vmid = g_process_ipc_info.vmid;
    if (tcb->tp) {
        if (!is_internal_tid(tcb->tp->tid)) {
            /* normal app thread: show Process ID, Thread ID, and exec name */
            fprintfmt(log_one_char, NULL, buf, "[P%u:T%u:%s] ", vmid, tcb->tp->tid, exec);
        } else {
            /* internal LibOS thread: show Process ID, Internal-thread ID, and exec name */
            fprintfmt(log_one_char, NULL, buf, "[P%u:i%u:%s] ", vmid,
                      tcb->tp->tid - INTERNAL_TID_BASE, exec);
        }
    } else if (g_process_ipc_info.vmid) {
        /* unknown thread (happens on process init): show Process ID and exec name */
        fprintfmt(log_one_char, NULL, buf, "[P%u:%s] ", vmid, exec);
    } else {
        /* unknown process (must never happen): show exec name */
        fprintfmt(log_one_char, NULL, buf, "[%s] ", exec);
    }

    buf->start = buf->end;
}

static void log_vprintf(const char* fmt, va_list ap) {
    vfprintfmt(log_one_char, NULL, shim_get_tcb()->log_buf, fmt, ap);
}

void _log(int level, const char* fmt, ...) {
    if (level <= g_log_level) {
        va_list ap;
        va_start(ap, fmt);
        // prepend prefix only on line starts
        if (shim_get_tcb()->log_buf->end == shim_get_tcb()->log_buf->start) {
            assert(0 <= level && (size_t)level < ARRAY_SIZE(log_level_to_prefix));
            log_always("%s", log_level_to_prefix[level]);
        }
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
