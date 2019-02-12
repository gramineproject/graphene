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
 * db_threading.c
 *
 * This file contain APIs to create, exit and yield a thread.
 */

#include "pal_defs.h"
#include "pal_freebsd_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_freebsd.h"
#include "pal_error.h"
#include "pal_debug.h"
#include "api.h"

#include <errno.h>
#include <signal.h>
#include <sys/mman.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/timespec.h>
#include <unistd.h>
#define THREAD_STACK_SIZE   (pal_state.alloc_align)

/* _DkThreadCreate for internal use. Create an internal thread
   inside the current process. The arguments callback and param
   specify the starting function and parameters */
int _DkThreadCreate (PAL_HANDLE * handle, int (*callback) (void *),
                     const void * param, int flags)
{
   void * child_stack = NULL;

    if (_DkVirtualMemoryAlloc(&child_stack, THREAD_STACK_SIZE, 0,
                              PAL_PROT_READ|PAL_PROT_WRITE) < 0)
        return -PAL_ERROR_NOMEM;

    // move child_stack to the top of stack. 
    child_stack += THREAD_STACK_SIZE;

    // align child_stack to 16 
    child_stack = ALIGN_DOWN_PTR(child_stack, 16);

    flags &= PAL_THREAD_MASK;

    assert(!flags); //FreeBSD does not support any more flags for rfork!

    int ret = rfork_thread(
                    RFPROC|RFNOWAIT|RFSIGSHARE|RFMEM,
                    child_stack,
                    callback,
                    (void *)param);

    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    PAL_HANDLE hdl = malloc(HANDLE_SIZE(thread));
    SET_HANDLE_TYPE(hdl, thread);
    hdl->thread.tid = ret;
    *handle = hdl;
    return 0;
}

int _DkThreadDelayExecution (unsigned long * duration)
{
    struct timespec sleeptime;
    struct timespec remainingtime;

    long sec = (unsigned long) *duration / 1000000;
    long microsec = (unsigned long) *duration - (sec * 1000000);

    sleeptime.tv_sec = sec;
    sleeptime.tv_nsec = microsec * 1000;

    int ret = INLINE_SYSCALL(nanosleep, 2, &sleeptime, &remainingtime);

    if (IS_ERR(ret)) {
        PAL_NUM remaining = remainingtime.tv_sec * 1000000 +
                            remainingtime.tv_nsec / 1000;

        *duration -= remaining;
        return -PAL_ERROR_INTERRUPTED;
    }

    return 0;
}

/* PAL call DkThreadYieldExecution. Yield the execution
   of the current thread. */
void _DkThreadYieldExecution (void)
{
    INLINE_SYSCALL(sched_yield, 0);
}

/* _DkThreadExit for internal use: Thread exiting */
void _DkThreadExit (void)
{
    INLINE_SYSCALL(exit, 1, 0);
}

int _DkThreadResume (PAL_HANDLE threadHandle)
{
    int ret = INLINE_SYSCALL(kill, 2, threadHandle->thread.tid, SIGCONT);

    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    return 0;
}

struct handle_ops thread_ops = {
    /* nothing */
};
