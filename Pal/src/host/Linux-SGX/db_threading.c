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

#include <list.h>

static PAL_LOCK thread_list_lock = LOCK_INIT;
DEFINE_LISTP(pal_handle_thread);
static LISTP_TYPE(pal_handle_thread) thread_list = LISTP_INIT;

struct thread_param {
    int (*callback) (void *);
    const void * param;
};

extern void * enclave_base;

void pal_start_thread (void)
{
    struct pal_handle_thread *new_thread = NULL, *tmp;

    _DkInternalLock(&thread_list_lock);
    listp_for_each_entry(tmp, &thread_list, list)
        if (!tmp->tcs) {
            new_thread = tmp;
            new_thread->tcs =
                enclave_base + GET_ENCLAVE_TLS(tcs_offset);
            break;
        }
    _DkInternalUnlock(&thread_list_lock);

    if (!new_thread)
        return;

    struct thread_param * thread_param =
            (struct thread_param *) new_thread->param;
    int (*callback) (void *) = thread_param->callback;
    const void * param = thread_param->param;
    free(thread_param);
    new_thread->param = NULL;
    SET_ENCLAVE_TLS(thread, new_thread);
    callback((void *) param);
}

/* _DkThreadCreate for internal use. Create an internal thread
   inside the current process. The arguments callback and param
   specify the starting function and parameters */
int _DkThreadCreate (PAL_HANDLE * handle, int (*callback) (void *),
                     const void * param, int flags)
{
    PAL_HANDLE new_thread = malloc(HANDLE_SIZE(thread));
    SET_HANDLE_TYPE(new_thread, thread);
    new_thread->thread.tcs = NULL;
    INIT_LIST_HEAD(&new_thread->thread, list);
    struct thread_param * thread_param = malloc(sizeof(struct thread_param));
    thread_param->callback = callback;
    thread_param->param = param;
    new_thread->thread.param = (void *) thread_param;

    _DkInternalLock(&thread_list_lock);
    listp_add_tail(&new_thread->thread, &thread_list, list);
    _DkInternalUnlock(&thread_list_lock);

    int ret = ocall_wake_thread(NULL);
    if (ret < 0)
        return ret;

    *handle = new_thread;
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
    ocall_sleep(NULL);
}

/* _DkThreadExit for internal use: Thread exiting */
void _DkThreadExit (void)
{
    ocall_exit(0);
}

int _DkThreadResume (PAL_HANDLE threadHandle)
{
    return ocall_wake_thread(threadHandle->thread.tcs);
}

int _DkThreadGetCurrent (PAL_HANDLE * threadHandle)
{
    *threadHandle = (PAL_HANDLE) GET_ENCLAVE_TLS(thread);
    return 0;
}

struct handle_ops thread_ops = {
    /* nothing */
};
