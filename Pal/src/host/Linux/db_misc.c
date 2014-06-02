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

/*
 * db_misc.c
 *
 * This file contains APIs for miscellaneous use.
 */

#include "pal_defs.h"
#include "pal_linux_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_error.h"
#include "pal_security.h"
#include "api.h"

#include <linux/time.h>
#include <asm/fcntl.h>

#ifdef __x86_64__
int __gettimeofday(struct timeval *tv, struct timezone *tz);
#endif

#if USE_VDSO_GETTIME == 1
# if USE_CLOCK_GETTIME == 1
long int (*__vdso_clock_gettime) (long int clk, struct timespec * tp);
# else
long int (*__vdso_gettimeofday) (struct timeval *, void *);
# endif
#endif

unsigned long _DkSystemTimeQuery (void)
{
#if USE_CLOCK_GETTIME == 1
    struct timespec time;
    int ret;

#if USE_VDSO_GETTIME == 1
    if (__vdso_clock_gettime) {
        ret = __vdso_clock_gettime(CLOCK_MONOTONIC, &time);
    } else {
#endif
        ret = INLINE_SYSCALL(clock_gettime, 2, CLOCK_MONOTONIC, &time);
#if USE_VDSO_GETTIME == 1
    }
#endif

    /* Come on, gettimeofday mostly never fails */
    if (IS_ERR(ret))
        return 0;

    /* in microseconds */
    return time.tv_sec * 1000000 + time.tv_nsec / 1000;
#else
    struct timeval time;
    int ret;

#if USE_VDSO_GETTIME == 1
    if (__vdso_gettimeofday) {
        ret = __vdso_gettimeofday(&time, NULL);
    } else {
#endif
#if defined(__x86_64__) && USE_VSYSCALL_GETTIME == 1
        ret = __gettimeofday(&time, NULL);
#else
        ret = INLINE_SYSCALL(gettimeofday, 2, &time, NULL);
#endif
#if USE_VDSO_GETTIME == 1
    }
#endif

    /* Come on, gettimeofday mostly never fails */
    if (IS_ERR(ret))
        return 0;

    /* in microseconds */
    return time.tv_sec * 1000000 + time.tv_usec;
#endif
}

int _DkRandomBitsRead (void * buffer, int size)
{
    if (!pal_sec_info.rand_gen) {
        int fd = INLINE_SYSCALL(open, 3, "/dev/urandom", O_RDONLY, 0);
        if (IS_ERR(fd))
            return -PAL_ERROR_DENIED;

        pal_sec_info.rand_gen = fd;
    }

    int bytes = INLINE_SYSCALL(read, 3, pal_sec_info.rand_gen, buffer, size);
    return IS_ERR(bytes) ? -PAL_ERROR_DENIED : bytes;
}

int _DkInstructionCacheFlush (const void * addr, size_t size)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}
