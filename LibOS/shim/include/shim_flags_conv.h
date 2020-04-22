/* Copyright (C) 2020 Invisible Things Lab
                      Michał Kowalczyk <mkow@invisiblethingslab.com>
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

/*
 * This file defines conversions between Linux syscall flags and PAL API flags.
 *
 * For Linux-based PALs there is pal_flag_conv.h in Linux-common, mirroring those conversions.
 */

#ifndef SHIM_FLAGS_CONV_H
#define SHIM_FLAGS_CONV_H

#include <asm/fcntl.h>
#include <asm/mman.h>
#include <linux/fcntl.h>

#include "assert.h"
#include "pal.h"

static inline int LINUX_PROT_TO_PAL(int prot, int map_flags) {
    assert(WITHIN_MASK(prot, PROT_READ | PROT_WRITE | PROT_EXEC));
    return (prot & PROT_READ  ? PAL_PROT_READ  : 0) |
           (prot & PROT_WRITE ? PAL_PROT_WRITE : 0) |
           (prot & PROT_EXEC  ? PAL_PROT_EXEC  : 0) |
           (map_flags & MAP_PRIVATE ? PAL_PROT_WRITECOPY : 0);
}

static inline int LINUX_ACCESS_TO_LINUX_OPEN(int access) {
    return (access & O_RDONLY ? PAL_ACCESS_RDONLY : 0) |
           (access & O_WRONLY ? PAL_ACCESS_WRONLY : 0) |
           (access & O_RDWR   ? PAL_ACCESS_RDWR   : 0) |
           (access & O_APPEND ? PAL_ACCESS_APPEND : 0);
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
