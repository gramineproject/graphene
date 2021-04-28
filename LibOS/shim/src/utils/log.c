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

void log_setprefix(shim_tcb_t* tcb) {
    if (g_log_level <= PAL_LOG_NONE)
        return;

    const char* exec = g_pal_control->executable;
    for (const char* it = exec; *it; it++)
        if (*it == ':' || *it == '/')
            exec = it + 1;

    uint32_t vmid = g_process_ipc_info.vmid;
    size_t total_len;
    if (tcb->tp) {
        if (!is_internal_tid(tcb->tp->tid)) {
            /* normal app thread: show Process ID, Thread ID, and exec name */
            total_len = snprintf(tcb->log_prefix, ARRAY_SIZE(tcb->log_prefix), "[P%u:T%u:%s] ",
                                 vmid, tcb->tp->tid, exec);
        } else {
            /* internal LibOS thread: show Process ID, Internal-thread ID, and exec name */
            total_len = snprintf(tcb->log_prefix, ARRAY_SIZE(tcb->log_prefix), "[P%u:i%u:%s] ",
                                 vmid, tcb->tp->tid - INTERNAL_TID_BASE, exec);
        }
    } else if (g_process_ipc_info.vmid) {
        /* unknown thread (happens on process init): show Process ID and exec name */
        total_len = snprintf(tcb->log_prefix, ARRAY_SIZE(tcb->log_prefix), "[P%u:%s] ", vmid,
                             exec);
    } else {
        /* unknown process (must never happen): show exec name */
        total_len = snprintf(tcb->log_prefix, ARRAY_SIZE(tcb->log_prefix), "[%s] ", exec);
    }
    if (total_len > ARRAY_SIZE(tcb->log_prefix) - 1) {
        /* exec name too long, snip it */
        const char* snip = "...] ";
        size_t snip_size = strlen(snip) + 1;
        memcpy(tcb->log_prefix + ARRAY_SIZE(tcb->log_prefix) - snip_size, snip, snip_size);
    }
}

static int buf_write_all(const char* str, size_t size, void* arg) {
    __UNUSED(arg);
    DkDebugLog((PAL_PTR)str, size);
    return 0;
}

void _log(int level, const char* fmt, ...) {
    if (level <= g_log_level) {
        struct print_buf buf = INIT_PRINT_BUF(buf_write_all);

        buf_puts(&buf, shim_get_tcb()->log_prefix);
        buf_puts(&buf, log_level_to_prefix[level]);

        va_list ap;
        va_start(ap, fmt);
        buf_vprintf(&buf, fmt, ap);
        va_end(ap);

        buf_flush(&buf);
    }
}

void log_always(const char* fmt, ...) {
    struct print_buf buf = INIT_PRINT_BUF(buf_write_all);

    buf_puts(&buf, shim_get_tcb()->log_prefix);

    va_list ap;
    va_start(ap, fmt);
    buf_vprintf(&buf, fmt, ap);
    va_end(ap);

    buf_flush(&buf);
}
