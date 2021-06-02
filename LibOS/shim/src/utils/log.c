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
#include "shim_lock.h"
#include "shim_process.h"

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

    lock(&g_process.fs_lock);

    const char* exec_name;
    if (tcb->tp && is_internal_tid(tcb->tp->tid)) {
        /* This is an internal thread, use "shim" as executable name */
        exec_name = "shim";
    } else if (g_process.exec) {
        if (g_process.exec->dentry) {
            exec_name = qstrgetstr(&g_process.exec->dentry->name);
        } else if (!qstrempty(&g_process.exec->uri)) {
            exec_name = qstrgetstr(&g_process.exec->uri);
            /* Skip everything before ':' and '/' */
            for (const char* it = exec_name; *it; it++) {
                if (*it == ':' || *it == '/') {
                    exec_name = it + 1;
                }
            }
        } else {
            /* Unknown executable name */
            exec_name = "?";
        }
    } else {
        /* `g_process.exec` not available yet, happens on process init */
        exec_name = "";
    }

    uint32_t vmid = g_self_vmid;
    size_t total_len;
    if (tcb->tp) {
        if (!is_internal_tid(tcb->tp->tid)) {
            /* normal app thread: show Process ID, Thread ID, and exec name */
            total_len = snprintf(tcb->log_prefix, ARRAY_SIZE(tcb->log_prefix), "[P%u:T%u:%s] ",
                                 vmid, tcb->tp->tid, exec_name);
        } else {
            /* internal LibOS thread: show Process ID, Internal-thread ID, and exec name */
            total_len = snprintf(tcb->log_prefix, ARRAY_SIZE(tcb->log_prefix), "[P%u:i%u:%s] ",
                                 vmid, tcb->tp->tid - INTERNAL_TID_BASE, exec_name);
        }
    } else if (vmid) {
        /* unknown thread (happens on process init): show just Process ID and exec name */
        total_len = snprintf(tcb->log_prefix, ARRAY_SIZE(tcb->log_prefix), "[P%u::%s] ", vmid,
                             exec_name);
    } else {
        /* unknown process (must never happen): show exec name */
        total_len = snprintf(tcb->log_prefix, ARRAY_SIZE(tcb->log_prefix), "[::%s] ", exec_name);
    }
    if (total_len > ARRAY_SIZE(tcb->log_prefix) - 1) {
        /* exec name too long, snip it */
        const char* snip = "...] ";
        size_t snip_size = strlen(snip) + 1;
        memcpy(tcb->log_prefix + ARRAY_SIZE(tcb->log_prefix) - snip_size, snip, snip_size);
    }

    unlock(&g_process.fs_lock);
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
