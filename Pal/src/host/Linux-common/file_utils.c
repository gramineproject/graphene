/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

#include <asm/errno.h>
#include <asm/fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include "api.h"
#include "linux_utils.h"
#include "sysdep-arch.h"

int read_text_file_to_cstr(const char* path, char** out) {
    long ret;
    char* buf = NULL;
    long fd = INLINE_SYSCALL(open, 3, path, O_RDONLY, 0);
    if (fd < 0) {
        ret = fd;
        goto out;
    }

    ret = INLINE_SYSCALL(lseek, 3, fd, 0, SEEK_END);
    if (ret < 0) {
        goto out;
    }
    size_t size = ret;

    ret = INLINE_SYSCALL(lseek, 3, fd, 0, SEEK_SET);
    if (ret < 0) {
        goto out;
    }

    if (size + 1 < size) {
        ret = -E2BIG; // int overflow
        goto out;
    }
    buf = malloc(size + 1);
    if (!buf) {
        ret = -ENOMEM;
        goto out;
    }

    size_t bytes_read = 0;
    while (bytes_read < size) {
        ret = INLINE_SYSCALL(read, 3, fd, buf + bytes_read, size - bytes_read);
        if (ret <= 0) {
            if (ret == -EINTR)
                continue;
            if (ret == 0)
                ret = -EINVAL; // unexpected EOF
            goto out;
        }
        bytes_read += ret;
    }
    buf[size] = '\0';
    *out = buf;
    buf = NULL;
    ret = 0;
out:
    if (fd >= 0) {
        long close_ret = INLINE_SYSCALL(close, 1, fd);
        if (ret == 0)
            ret = close_ret;
    }
    free(buf);
    return (int)ret;
}
