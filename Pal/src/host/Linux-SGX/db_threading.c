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
 * db_threading.c
 *
 * This file contain APIs to create, exit and yield a thread.
 */

#include "pal_defs.h"
#include "pal_linux_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_error.h"
#include "pal_debug.h"
#include "api.h"
#include "ecall_types.h"

#include <linux/signal.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/wait.h>

#include <linux_list.h>

/* default size of a new thread */
#define PAL_THREAD_STACK_SIZE allocsize

struct thread_param {
    int (*callback) (void *);
    const void * param;
    PAL_HANDLE event, thread;
};

void pal_start_thread (void * __param)
{
    struct thread_param * pal_param = (struct thread_param *) __param;

    int (*callback) (void *) = *(void * volatile *) &pal_param->callback;
    void *param = *(void * volatile *) &pal_param->param;

    _DkEventWait(pal_param->event);
    volatile PAL_HANDLE thread = pal_param->thread;
    _DkEventDestroy(pal_param->event);
    free(pal_param);

    ENCLAVE_TLS(thread) = thread;

    callback(param);
}

/* _DkThreadCreate for internal use. Create an internal thread
   inside the current process. The arguments callback and param
   specify the starting function and parameters */
int _DkThreadCreate (PAL_HANDLE * handle, int (*callback) (void *),
                     const void * param, int flags)
{
    struct thread_param * pal_param = malloc(sizeof(struct thread_param));
    pal_param->callback = callback;
    pal_param->param = param;
    _DkEventCreate(&pal_param->event, false, true);
    flags &= PAL_THREAD_MASK;

    unsigned int tid = 0;
    int ret = ocall_clone_thread(pal_start_thread, pal_param, NULL, &tid);
    if (ret < 0)
        return ret;

    assert(tid);
    PAL_HANDLE hdl = malloc(HANDLE_SIZE(thread));
    SET_HANDLE_TYPE(hdl, thread);
    hdl->thread.tid = tid;
    pal_param->thread = *handle = hdl;
    _DkEventSet(pal_param->event, 1);
    return 0;
}

int _DkThreadDelayExecution (unsigned long * duration)
{
    return ocall_sleep(duration);
}

/* PAL call DkThreadYieldExecution. Yield the execution
   of the current thread. */
void _DkThreadYieldExecution (void)
{
    ocall_schedule(0);
}

/* _DkThreadExit for internal use: Thread exiting */
void _DkThreadExit (void)
{
    ocall_exit();
}

int _DkThreadResume (PAL_HANDLE threadHandle)
{
    return ocall_schedule(threadHandle->thread.tid);
}

int _DkThreadGetCurrent (PAL_HANDLE * threadHandle)
{
    *threadHandle = (PAL_HANDLE) ENCLAVE_TLS(thread);
    return 0;
}

struct handle_ops thread_ops = {
    /* nothing */
};
