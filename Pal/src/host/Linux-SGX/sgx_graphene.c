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

#include <pal.h>
#include <pal_error.h>
#include <linux_list.h>
#include <atomic.h>

#include <linux/futex.h>
#include <errno.h>

#include "sgx_internal.h"

#define MUTEX_SPINLOCK_TIMES    20

static int _DkMutexLock (struct mutex_handle * mut)
{
    int i, c = 0;
    int ret;
    struct atomic_int * m = &mut->value;

    /* Spin and try to take lock */
    for (i = 0; i < MUTEX_SPINLOCK_TIMES; i++) {
        c = atomic_dec_and_test(m);
        if (c)
            goto success;
        cpu_relax();
    }

    /* The lock is now contended */

    while (!c) {
        int val = atomic_read(m);
        if (val == 1)
            goto again;

        ret = INLINE_SYSCALL(futex, 6, m, FUTEX_WAIT, val, NULL, NULL, 0);

        if (IS_ERR(ret) &&
            ERRNO(ret) != EWOULDBLOCK &&
            ERRNO(ret) != EINTR) {
            ret = -PAL_ERROR_DENIED;
            goto out;
        }

again:
        /* Upon wakeup, we still need to check whether mutex is unlocked or
         * someone else took it.
         * If c==0 upon return from xchg (i.e., the older value of m==0), we
         * will exit the loop. Else, we sleep again (through a futex call).
         */
        c = atomic_dec_and_test(m);
    }

success:
    ret = 0;
out:
    return ret;
}

static int _DkMutexUnlock (struct mutex_handle * mut)
{
    int ret = 0;
    int must_wake = 0;
    struct atomic_int * m = &mut->value;

    /* Unlock, and if not contended then exit. */
    if (atomic_read(m) < 0)
        must_wake = 1;

    atomic_set(m, 1);

    if (must_wake) {
        /* We need to wake someone up */
        ret = INLINE_SYSCALL(futex, 6, m, FUTEX_WAKE, 1, NULL, NULL, 0);
    }

    if (IS_ERR(ret)) {
        ret = -PAL_ERROR_TRYAGAIN;
        goto out;
    }

    ret = 0;
out:
    return ret;
}

static struct mutex_handle slabmgr_lock;
static void * untrusted_slabmgr = NULL;

#define system_lock()   _DkMutexLock(&slabmgr_lock)
#define system_unlock() _DkMutexUnlock(&slabmgr_lock)

#define PAGE_SIZE (pagesize)

#define STARTUP_SIZE    8

static inline void * __malloc (int size)
{
    void * addr = NULL;
    addr = (void *) INLINE_SYSCALL(mmap, 6, NULL, size,
                                   PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS,
                                   -1, 0);
    if (IS_ERR_P(addr))
        return NULL;
    return addr;
}

#define system_malloc(size) __malloc(size)

static inline void __free (void * addr, int size)
{
    INLINE_SYSCALL(munmap, 2, addr, size);
}

#define system_free(addr, size) __free(addr, size)

#include "slabmgr.h"

int init_untrusted_allocator (struct pal_sec * pal_sec)
{
    if (!untrusted_slabmgr) {
        untrusted_slabmgr = create_slab_mgr();
        if (!untrusted_slabmgr)
            return -PAL_ERROR_NOMEM;
    }

    pal_sec->untrusted_allocator.alignment = pagesize;
    pal_sec->untrusted_allocator.slabmgr = untrusted_slabmgr;
    pal_sec->untrusted_allocator.lock = &slabmgr_lock;
    return 0;
}

void * malloc_untrusted (int size)
{
    void * ptr = slab_alloc((SLAB_MGR) untrusted_slabmgr, size);

    /* the slab manger will always remain at least one byte of padding,
       so we can feel free to assign an offset at the byte prior to
       the pointer */
    if (ptr)
        *(((unsigned char *) ptr) - 1) = 0;

    return ptr;
}

void free_untrusted (void * ptr)
{
    ptr -= *(((unsigned char *) ptr) - 1);
    slab_free((SLAB_MGR) untrusted_slabmgr, ptr);
}

int _DkEventSet (PAL_HANDLE event, int wakeup)
{
    int ret = 0;

    if (event->event.isnotification) {
        // Leave it signaled, wake all
        if (atomic_cmpxchg(&event->event.signaled, 0, 1) == 0) {
            int nwaiters = atomic_read(&event->event.nwaiters);
            if (nwaiters) {
                if (wakeup != -1 && nwaiters > wakeup)
                    nwaiters = wakeup;

                ret = INLINE_SYSCALL(futex, 6, &event->event.signaled,
                                     FUTEX_WAKE, nwaiters, NULL, NULL, 0);
                if (IS_ERR(ret))
                    atomic_set(&event->event.signaled, 0);
            }
        }
    } else {
        // Only one thread wakes up, leave unsignaled
        ret = INLINE_SYSCALL(futex, 6, &event->event.signaled, FUTEX_WAKE, 1,
                             NULL, NULL, 0);
    }

    return IS_ERR(ret) ? PAL_ERROR_TRYAGAIN : ret;
}

int _DkEventWait (PAL_HANDLE event)
{
    int ret = 0;

    if (!event->event.isnotification || !atomic_read(&event->event.signaled)) {
        atomic_inc(&event->event.nwaiters);

        do {
            ret = INLINE_SYSCALL(futex, 6, &event->event.signaled, FUTEX_WAIT,
                                  0, NULL, NULL, 0);

            if (IS_ERR(ret)) {
                if (ERRNO(ret) == EWOULDBLOCK) {
                    ret = 0;
                } else {
                    ret = -PAL_ERROR_DENIED;
                    break;
                }
            }
        } while (event->event.isnotification &&
                 !atomic_read(&event->event.signaled));

        atomic_dec(&event->event.nwaiters);
    }

    return ret;
}

#define PRINTBUF_SIZE        256

struct printbuf {
    int idx;    // current buffer index
    int cnt;    // total bytes printed so far
    char buf[PRINTBUF_SIZE];
};

static void
fputch(void * f, int ch, struct printbuf * b)
{
    b->buf[b->idx++] = ch;
    if (b->idx == PRINTBUF_SIZE-1) {
        INLINE_SYSCALL(write, 3, 2, b->buf, b->idx);
        b->idx = 0;
    }
    b->cnt++;
}

static int
vprintf(const char * fmt, va_list *ap)
{
    struct printbuf b;

    b.idx = 0;
    b.cnt = 0;
    vfprintfmt((void *) &fputch, NULL, &b, fmt, ap);
    INLINE_SYSCALL(write, 3, 2, b.buf, b.idx);

    return b.cnt;
}

int
pal_printf(const char * fmt, ...)
{
    va_list ap;
    int cnt;

    va_start(ap, fmt);
    cnt = vprintf(fmt, &ap);
    va_end(ap);

    return cnt;
}
