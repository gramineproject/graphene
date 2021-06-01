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

int g_log_level = LOG_LEVEL_NONE;

/* NOTE: We could add "libos" prefix to the below strings for more fine-grained log info */
static const char* log_level_to_prefix[] = {
    [LOG_LEVEL_NONE]    = "",
    [LOG_LEVEL_ERROR]   = "error: ",
    [LOG_LEVEL_WARNING] = "warning: ",
    [LOG_LEVEL_DEBUG]   = "debug: ",
    [LOG_LEVEL_TRACE]   = "trace: ",
    [LOG_LEVEL_ALL]     = "", // not a valid entry actually (no public wrapper uses this log level)
};

void log_setprefix(shim_tcb_t* tcb) {
    if (g_log_level <= LOG_LEVEL_NONE)
        return;

    uint32_t vmid = g_self_vmid;
    size_t total_len;
    if (tcb->tp) {
        if (!is_internal_tid(tcb->tp->tid)) {
            /* normal app thread: show Process ID and Thread ID */
            total_len = snprintf(tcb->log_prefix, ARRAY_SIZE(tcb->log_prefix), "[P%u:T%u] ",
                                 vmid, tcb->tp->tid);
        } else {
            /* internal LibOS thread: show Process ID and Internal-thread ID */
            total_len = snprintf(tcb->log_prefix, ARRAY_SIZE(tcb->log_prefix), "[P%u:i%u] ",
                                 vmid, tcb->tp->tid - INTERNAL_TID_BASE);
        }
    } else if (vmid) {
        /* unknown thread (happens on process init): show Process ID */
        total_len = snprintf(tcb->log_prefix, ARRAY_SIZE(tcb->log_prefix), "[P%u] ", vmid);
    } else {
        /* unknown process (must never happen) */
        total_len = snprintf(tcb->log_prefix, ARRAY_SIZE(tcb->log_prefix), "[???] ");
    }
    assert(total_len + 1 <= ARRAY_SIZE(tcb->log_prefix));
}

static int buf_write_all(const char* str, size_t size, void* arg) {
    __UNUSED(arg);
    DkDebugLog((PAL_PTR)str, size);
    return 0;
}

void shim_log(int level, const char* fmt, ...) {
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
