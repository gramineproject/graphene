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
 * db_mutex.c
 *
 * This file contains APIs that provide operations of (futex based) mutexes.
 * Based on "Mutexes and Condition Variables using Futexes"
 * (http://locklessinc.com/articles/mutex_cv_futex)
 */

#include "pal_defs.h"
#include "pal_linux_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_error.h"
#include "pal_debug.h"
#include "api.h"

#include <linux/futex.h>
#include <limits.h>
#include <atomic.h>
#include <linux/time.h>

#ifdef __i386__
# define barrier()       asm volatile("" ::: "memory");
# define rmb()           asm volatile("lock; addl $0,0(%%esp)" ::: "memory")
# define cpu_relax()     asm volatile("rep; nop" ::: "memory");
#endif

#ifdef __x86_64__
# include <unistd.h>
# define barrier()       asm volatile("" ::: "memory");
# define rmb()           asm volatile("lfence" ::: "memory")
# define cpu_relax()     asm volatile("rep; nop" ::: "memory");
#endif

#define MUTEX_SPINLOCK_TIMES    100

int _DkMutexLockTimeout (struct mutex_handle * m, int timeout)
{
    int ret = 0;
#ifdef DEBUG_MUTEX
    int tid = INLINE_SYSCALL(gettid, 0);
#endif

    if (timeout == -1)
        return -_DkMutexLock(m);

    if (!xchg(&m->b.locked, 1))
        goto success;

    if (timeout == 0) {
        ret = -PAL_ERROR_TRYAGAIN;
        goto out;
    }

    unsigned long waittime = timeout;

    while (xchg(&m->u, 257) & 1) {
        ret = ocall_futex((int *) m, FUTEX_WAIT, 257, timeout ? &waittime : NULL);
        if (ret < 0) {
            if (ret == -PAL_ERROR_TRYAGAIN) {
                xchg(&m->b.contended, 0);
                goto out;
            }
#ifdef DEBUG_MUTEX
            printf("futex failed (err = %d)\n", ERRNO(ret));
#endif
            goto out;
        }
    }

success:
#ifdef DEBUG_MUTEX
    m->owner = tid;
#endif
    ret = 0;
out:
#ifdef DEBUG_MUTEX
    if (ret < 0)
        printf("mutex failed (%s, tid = %d)\n", PAL_STRERROR(ret), tid);
#endif
    return ret;
}

int _DkMutexLock (struct mutex_handle * m)
{
    int ret = 0, i;
#ifdef DEBUG_MUTEX
    int tid = INLINE_SYSCALL(gettid, 0);
#endif

    /* Spin and try to take lock */
    for (i = 0; i < MUTEX_SPINLOCK_TIMES; i++) {
        if (!xchg(&m->b.locked, 1))
            goto success;
        cpu_relax();
    }

    // Mutex is union of u8 array and u32; this assumes a little-endian machine.
    while (xchg(&m->u, 257) & 1) {
        // This is broken. The mutex is in enclave memory, the URTS can't
        // do FUTEX_WAIT on it. This call will always fail and the next level
        // up needs to retry.
        ret = ocall_futex((int *) m, FUTEX_WAIT, 257, NULL);
        if (ret < 0 &&
            ret != -PAL_ERROR_TRYAGAIN) {
#ifdef DEBUG_MUTEX
            printf("futex failed (err = %d)\n", ERRNO(ret));
#endif
            goto out;
        }
    }

success:
#ifdef DEBUG_MUTEX
    m->owner = tid;
#endif
    ret = 0;
out:
#ifdef DEBUG_MUTEX
    if (ret < 0)
        printf("mutex failed (%s, tid = %d)\n", PAL_STRERROR(ret), tid);
#endif
    return ret;
}

int _DkMutexUnlock (struct mutex_handle * m)
{
    int ret = 0, i;

#ifdef DEBUG_MUTEX
    m->owner = 0;
#endif

    /* Unlock, and if not contended then exit. */
    if ((m->u == 1) && (cmpxchg(&m->u, 1, 0) == 1)) return 0;
    m->b.locked = 0;
    barrier();

    /* See if somebody else takes the lock */
    for (i = 0; i < MUTEX_SPINLOCK_TIMES * 2; i++) {
        if (m->b.locked)
            goto success;
        cpu_relax();
    }

    m->b.contended = 0;

    /* Nobody took it, we need to wake someone up */
    ocall_futex((int *) m, FUTEX_WAKE, 1, NULL);

success:
    ret = 0;
out:
    return ret;
}
