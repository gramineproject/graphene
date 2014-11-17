/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2014 OSCAR lab, Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#ifndef PAL_LINUX_H
#define PAL_LINUX_H

#include "pal_defs.h"
#include "pal_linux_defs.h"
#include "pal.h"

#include <sys/syscall.h>

#ifdef __x86_64__
# include "sysdep-x86_64.h"
#endif

#define IS_ERR INTERNAL_SYSCALL_ERROR
#define IS_ERR_P INTERNAL_SYSCALL_ERROR_P
#define ERRNO INTERNAL_SYSCALL_ERRNO
#define ERRNO_P INTERNAL_SYSCALL_ERRNO_P

extern struct pal_linux_config {
    unsigned int    pid, uid, gid;
    __sigset_t      sigset;
    bool            noexec;
} pal_linux_config;

#include <asm/mman.h>

#ifdef INLINE_SYSCALL
# ifdef __i386__
#  define ARCH_MMAP(addr, len, prot, flags, fd, offset)          \
    ({                                                           \
        struct mmap_arg_struct {                                 \
            unsigned long addr;                                  \
            unsigned long len;                                   \
            unsigned long prot;                                  \
            unsigned long flags;                                 \
            unsigned long fd;                                    \
            unsigned long offset;                                \
        } args = {  .addr   = (unsigned long) (addr),            \
                    .len    = (unsigned long) (len),             \
                    .prot   = (unsigned long) (prot),            \
                    .flags  = (unsigned long) (flags),           \
                    .fd     = (unsigned long) (fd),              \
                    .offset = (unsigned long) (offset), };       \
        INLINE_SYSCALL(mmap, 1, &args);                          \
    })
# else
#  define ARCH_MMAP(addr, len, prot, flags, fd, offset) \
    INLINE_SYSCALL(mmap, 6, (addr), (len), (prot), (flags), (fd), (offset))
# endif
#else
# error "INLINE_SYSCALL not supported"
#endif

#define ARCH_FORK() INLINE_SYSCALL(clone, 4, CLONE_CHILD_SETTID, 0, \
                                   NULL, &pal_linux_config.pid)

#define ARCH_VFORK() INLINE_SYSCALL(clone, 4, CLONE_VM|CLONE_VFORK, 0, \
                                    NULL, NULL)

#define PRESET_PAGESIZE (1 << 12)

#define DEFAULT_BACKLOG     2048

static inline int HOST_FLAGS (int alloc_type, int prot)
{
    return ((alloc_type & PAL_ALLOC_32BIT) ? MAP_32BIT : 0) |
           ((alloc_type & PAL_ALLOC_RESERVE) ? MAP_NORESERVE|MAP_UNINITIALIZED : 0) |
           ((prot & PAL_PROT_WRITECOPY) ? MAP_PRIVATE : MAP_SHARED);
}

static inline int HOST_PROT (int prot)
{
    return prot & (PAL_PROT_READ|PAL_PROT_WRITE|PAL_PROT_EXEC);
}

int __clone (int (*__fn) (void * __arg), void * __child_stack,
             int __flags, const void * __arg, ...);

#define ACCESS_R    4
#define ACCESS_W    2
#define ACCESS_X    1

struct stat;
bool stataccess (struct stat * stats, int acc);

#if USE_VDSO_GETTIME == 1
# if USE_CLOCK_GETTIME == 1
struct timespec;
long int (*__vdso_clock_gettime) (long int clk, struct timespec * tp);
# else
struct timeval;
long int (*__vdso_gettimeofday) (struct timeval *, void *);
# endif
#endif

#endif /* PAL_LINUX_H */
