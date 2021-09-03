/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Invisible Things Lab
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 * Copyright (C) 2021 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

/*
 * This file defines conversions between Linux syscall flags and PAL API flags.
 *
 * For Linux-based PALs there is pal_flag_conv.h in Linux-common, mirroring those conversions.
 */

#ifndef SHIM_FLAGS_CONV_H
#define SHIM_FLAGS_CONV_H

#include <asm/fcntl.h>
#include <linux/fcntl.h>
#include <linux/mman.h>

#include "assert.h"
#include "pal.h"
#include "shim_internal.h"

static inline int LINUX_PROT_TO_PAL(int prot, int map_flags) {
    assert(WITHIN_MASK(prot, PROT_NONE | PROT_READ | PROT_WRITE | PROT_EXEC
                                | PROT_GROWSDOWN | PROT_GROWSUP));
    return (prot & PROT_READ  ? PAL_PROT_READ  : 0) |
           (prot & PROT_WRITE ? PAL_PROT_WRITE : 0) |
           (prot & PROT_EXEC  ? PAL_PROT_EXEC  : 0) |
           (map_flags & MAP_PRIVATE ? PAL_PROT_WRITECOPY : 0);
}

static inline int LINUX_OPEN_FLAGS_TO_PAL_ACCESS(int access) {
    int ret = 0;
    switch (access & O_ACCMODE) {
        case O_RDONLY:
            ret = PAL_ACCESS_RDONLY;
            break;
        case O_WRONLY:
            ret = PAL_ACCESS_WRONLY;
            break;
        case O_RDWR:
            ret = PAL_ACCESS_RDWR;
            break;
        default:
            BUG();
    }
    if (access & O_APPEND) {
        /* FIXME: Currently PAL does not support appending. */
    }
    return ret;
}

static inline int LINUX_OPEN_FLAGS_TO_PAL_CREATE(int flags) {
    if (WITHIN_MASK(O_CREAT | O_EXCL, flags))
        return PAL_CREATE_ALWAYS;
    if (flags & O_CREAT)
        return PAL_CREATE_TRY;
    return 0;
}

static inline int LINUX_OPEN_FLAGS_TO_PAL_OPTIONS(int flags) {
    return (flags & O_CLOEXEC  ? PAL_OPTION_CLOEXEC  : 0) |
           (flags & O_NONBLOCK ? PAL_OPTION_NONBLOCK : 0);
}

#endif /* SHIM_FLAGS_CONV_H */
