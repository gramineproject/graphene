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
 * This file defines conversions between various PAL API flags and the flags used by Linux syscalls.
 *
 * The counterpart of this file is shim_flag_conv.h in LibOS.
 */

#ifndef PAL_FLAGS_CONV_H
#define PAL_FLAGS_CONV_H

#undef __GLIBC__
#include <asm/fcntl.h>
#include <linux/mman.h>
#include <linux/stat.h>
#include <sys/types.h>

#include "assert.h"
#include "pal.h"

static inline int PAL_MEM_FLAGS_TO_LINUX(int alloc_type, int prot) {
    assert(WITHIN_MASK(alloc_type, PAL_ALLOC_MASK));
    assert(WITHIN_MASK(prot,       PAL_PROT_MASK));

    return (alloc_type & PAL_ALLOC_RESERVE ? MAP_NORESERVE | MAP_UNINITIALIZED : 0) |
           (prot & PAL_PROT_WRITECOPY      ? MAP_PRIVATE : MAP_SHARED);
}

static inline int PAL_PROT_TO_LINUX(int prot) {
    assert(WITHIN_MASK(prot, PAL_PROT_MASK));
    return (prot & PAL_PROT_READ  ? PROT_READ  : 0) |
           (prot & PAL_PROT_WRITE ? PROT_WRITE : 0) |
           (prot & PAL_PROT_EXEC  ? PROT_EXEC  : 0);
}

static inline int PAL_ACCESS_TO_LINUX_OPEN(int access) {
    assert(WITHIN_MASK(access, PAL_ACCESS_MASK));
    return (access & PAL_ACCESS_RDONLY ? O_RDONLY : 0) |
           (access & PAL_ACCESS_WRONLY ? O_WRONLY : 0) |
           (access & PAL_ACCESS_RDWR   ? O_RDWR   : 0) |
           (access & PAL_ACCESS_APPEND ? O_APPEND : 0);
}

static inline int PAL_CREATE_TO_LINUX_OPEN(int create) {
    assert(create == 0 || create == PAL_CREATE_TRY || create == PAL_CREATE_ALWAYS);
    return (create & PAL_CREATE_TRY    ? O_CREAT          : 0) |
           (create & PAL_CREATE_ALWAYS ? O_CREAT | O_EXCL : 0);
}

static inline int PAL_OPTION_TO_LINUX_OPEN(int options) {
    assert(WITHIN_MASK(options, PAL_OPTION_CLOEXEC | PAL_OPTION_NONBLOCK));
    return (options & PAL_OPTION_CLOEXEC  ? O_CLOEXEC  : 0) |
           (options & PAL_OPTION_NONBLOCK ? O_NONBLOCK : 0);
}

#endif /* PAL_FLAGS_CONV_H */
