/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

#include "assert.h"
#include "linux_utils.h"
#include "pal_debug.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "perm.h"
#include "sgx_log.h"

#define LOG_BUF_SIZE 256

static const char* log_level_to_prefix[] = {
    [PAL_LOG_NONE]    = "", // not a valid entry actually (no public wrapper uses this log level)
    [PAL_LOG_ERROR]   = "error: ",
    [PAL_LOG_WARNING] = "warning: ",
    [PAL_LOG_DEBUG]   = "debug: ",
    [PAL_LOG_TRACE]   = "trace: ",
    [PAL_LOG_ALL]     = "", // same as for PAL_LOG_NONE
};

struct log_buf {
    int fd;
    size_t end;
    char buf[LOG_BUF_SIZE];
};

int g_urts_log_level = PAL_LOG_DEFAULT_LEVEL;
int g_urts_log_fd = PAL_LOG_DEFAULT_FD;

int urts_log_init(const char* path) {
    int ret;

    if (g_urts_log_fd != PAL_LOG_DEFAULT_FD) {
        ret = INLINE_SYSCALL(close, 1, g_urts_log_fd);
        g_urts_log_fd = PAL_LOG_DEFAULT_FD;
        if (ret < 0)
            return ret;
    }

    ret = INLINE_SYSCALL(open, 3, path, O_WRONLY | O_APPEND | O_CREAT, PERM_rw_______);
    if (ret < 0)
        return ret;
    g_urts_log_fd = ret;
    return 0;
}

static int output_char(void* f, int ch, void* buf_) {
    __UNUSED(f);
    int ret = 0;
    struct log_buf* buf = (struct log_buf*)buf_;

    buf->buf[buf->end++] = ch;
    if (ch == '\n' || buf->end == LOG_BUF_SIZE) {
        ret = write_all(buf->fd, buf->buf, buf->end);
        buf->end = 0;
    }
    return ret;
}

static void print_to_fd(int fd, const char* fmt, va_list ap) {
    struct log_buf buf;

    buf.fd = fd;
    buf.end = 0;
    vfprintfmt(output_char, NULL, &buf, fmt, ap);
    write_all(fd, buf.buf, buf.end);
    // No error handling, as `_urts_log` doesn't return errors anyways.
}

// TODO: Remove this and always use log_*.
void pal_printf(const char* fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    print_to_fd(g_urts_log_fd, fmt, ap);
    va_end(ap);
}


void _urts_log(int level, const char* fmt, ...) {
    if (level <= g_urts_log_level) {
        va_list ap;
        va_start(ap, fmt);
        assert(0 <= level && (size_t)level < ARRAY_SIZE(log_level_to_prefix));
        urts_log_always("%s", log_level_to_prefix[level]);
        print_to_fd(g_urts_log_fd, fmt, ap);
        va_end(ap);
    }
}

void urts_log_always(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    print_to_fd(g_urts_log_fd, fmt, ap);
    va_end(ap);
}
