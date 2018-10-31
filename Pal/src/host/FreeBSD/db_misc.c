/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2014 Stony Brook University
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
 * db_misc.c
 *
 * This file contains APIs for miscellaneous use.
 */

#include "pal_defs.h"
#include "pal_freebsd_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_freebsd.h"
#include "pal_error.h"
#include "pal_security.h"
#include "api.h"

#include <sys/time.h>
#include <fcntl.h>

unsigned long _DkSystemTimeQuery (void)
{
#if USE_CLOCK_GETTIME == 1
    struct timespec time;
    int ret;

        ret = INLINE_SYSCALL(clock_gettime, 2, CLOCK_MONOTONIC, &time);

    /* Come on, gettimeofday mostly never fails */
    if (IS_ERR(ret))
        return 0;

    /* in microseconds */
    return 1000000ULL * time.tv_sec + time.tv_nsec / 1000;
#else
    struct timeval time;
    int ret;

        ret = INLINE_SYSCALL(gettimeofday, 2, &time, NULL);

    /* Come on, gettimeofday mostly never fails */
    if (IS_ERR(ret))
        return 0;

    /* in microseconds */
    return 1000000ULL * time.tv_sec + time.tv_usec;
#endif
}

#if USE_ARCH_RDRAND == 1
int _DkRandomBitsRead (void * buffer, int size)
{
    int total_bytes = 0;
    do {
        unsigned long rand;
        asm volatile (".Lretry: rdrand %%rax\r\n jnc .Lretry\r\n"
                      : "=a"(rand) :: "memory");

        if (total_bytes + sizeof(rand) <= size) {
            *(unsigned long *) (buffer + total_bytes) = rand;
            total_bytes += sizeof(rand);
        } else {
            for (int i = 0 ; i < size - total_bytes ; i++)
                *(unsigned char *) (buffer + total_bytes + i) = ((unsigned char *) &rand)[i];
            total_bytes = size;
        }
    } while (total_bytes < size);
    return total_bytes;
}
#else
int _DkRandomBitsRead (void * buffer, int size)
{
    if (!pal_sec.rand_gen) {
        int rand = INLINE_SYSCALL(open, 3, "/dev/urandom", O_RDONLY, 0);
        if (IS_ERR(rand))
            return -PAL_ERROR_DENIED;

        pal_sec.rand_gen = rand;
    }

    int total_bytes = 0;
    do {
        int bytes = INLINE_SYSCALL(read, 3, pal_sec.rand_gen,
                                   buffer + total_bytes, size - total_bytes);
        if (IS_ERR(bytes))
            return -PAL_ERROR_DENIED;

        total_bytes += bytes;
    } while (total_bytes < size);

    return total_bytes;
}
#endif

#if defined(__i386__)
#include <ldt.h>
#else
#include <x86/sysarch.h>
#endif

int _DkSegmentRegisterSet (int reg, const void * addr)
{
    int ret = 0;

#if defined(__i386__)
    struct user_desc u_info;

    ret = INLINE_SYSCALL(sysarch, 2, I386_GET_FSBASE, &u_info);

    if (IS_ERR(ret))
        return NULL;

    u_info->entry_number = -1;
    u_info->base_addr = (unsigned int) addr;

    ret = INLINE_SYSCALL(sysarch, 2, I386_SET_FSBASE, &u_info);
#else
    if (reg == PAL_SEGMENT_FS) {
        ret = INLINE_SYSCALL(sysarch, 2, AMD64_SET_FSBASE, &addr);
    } else if (reg == PAL_SEGMENT_GS) {
        ret = INLINE_SYSCALL(sysarch, 2, AMD64_SET_GSBASE, &addr);
    } else {
        return -PAL_ERROR_INVAL;
    }
#endif
    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    return 0;
}

int _DkSegmentRegisterGet (int reg, void ** addr)
{
    int ret;

#if defined(__i386__)
    struct user_desc u_info;

    ret = INLINE_SYSCALL(sysarch, 2, I386_GET_FSBASE, &u_info);

    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    *addr = (void *) u_info->base_addr;
#else
    unsigned long ret_addr;

    if (reg == PAL_SEGMENT_FS) {
        ret = INLINE_SYSCALL(sysarch, 2, AMD64_GET_FSBASE, &ret_addr);
    } else if (reg == PAL_SEGMENT_GS) {
        ret = INLINE_SYSCALL(sysarch, 2, AMD64_GET_GSBASE, &ret_addr);
    } else {
        return -PAL_ERROR_INVAL;

    }

    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    *addr = (void *) ret_addr;
#endif

    return 0;
}

int _DkInstructionCacheFlush (const void * addr, int size)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}
static PAL_LOCK lock = LOCK_INIT;
static unsigned long randval = 0;

static int init_randgen (void)
{
    unsigned long val;

    if (_DkRandomBitsRead(&val, sizeof(val)) < sizeof(val))
        return -PAL_ERROR_DENIED;

    _DkInternalLock(&lock);
    randval = val;
    _DkInternalUnlock(&lock);
    return 0;
}

int getrand (void * buffer, size_t size)
{
    unsigned long val;
    size_t bytes = 0;

    int ret = init_randgen();
    if (ret < 0)
        return ret;

    _DkInternalLock(&lock);
    val = randval;
    randval = hash64(~randval);
    _DkInternalUnlock(&lock);

    while (bytes + sizeof(uint64_t) <= size) {
        *(uint64_t *) (buffer + bytes) = val;
        val = hash64(val);
        bytes += sizeof(uint64_t);
    }

    if (bytes < size) {
        memcpy(buffer + bytes, &val, size - bytes);
        val = hash64(val);
    }

    _DkInternalLock(&lock);
    randval = val;
    _DkInternalUnlock(&lock);
    return 0;
}

int _DkCpuIdRetrieve (unsigned int leaf, unsigned int subleaf,
                      unsigned int values[4])
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}
