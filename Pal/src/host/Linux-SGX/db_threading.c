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
#include "pal_linux_error.h"
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

/*
 * We do not currently handle tid counter wrap-around, and could, in
 * principle, end up with two threads with the same ID. This is ok, as strict
 * uniqueness is not required; the tid is only used for debugging. We could
 * ensure uniqueness if needed in the future
 */
static PAL_IDX pal_assign_tid(void)
{
    static struct atomic_int tid = ATOMIC_INIT(0);
    return _atomic_add(1, &tid);
}

void pal_start_thread (void)
{
    struct pal_handle_thread *new_thread = NULL, *tmp;

    _DkInternalLock(&thread_list_lock);
    LISTP_FOR_EACH_ENTRY(tmp, &thread_list, list)
        if (!tmp->tcs) {
            new_thread = tmp;
            new_thread->tid = pal_assign_tid();
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
    SET_ENCLAVE_TLS(ready_for_exceptions, 1UL);
    PAL_TCB* pal_tcb = pal_get_tcb();
    memset(&pal_tcb->libos_tcb, 0, sizeof(pal_tcb->libos_tcb));
    callback((void *) param);
    _DkThreadExit(/*clear_child_tid=*/NULL);
}

/* _DkThreadCreate for internal use. Create an internal thread
   inside the current process. The arguments callback and param
   specify the starting function and parameters */
int _DkThreadCreate (PAL_HANDLE * handle, int (*callback) (void *),
                     const void * param)
{
    PAL_HANDLE new_thread = malloc(HANDLE_SIZE(thread));
    SET_HANDLE_TYPE(new_thread, thread);
    /*
     * tid will be filled later by pal_start_thread()
     * tid is cleared to avoid random value here.
     */
    new_thread->thread.tid = 0;
    new_thread->thread.tcs = NULL;
    INIT_LIST_HEAD(&new_thread->thread, list);
    struct thread_param * thread_param = malloc(sizeof(struct thread_param));
    thread_param->callback = callback;
    thread_param->param = param;
    new_thread->thread.param = (void *) thread_param;

    _DkInternalLock(&thread_list_lock);
    LISTP_ADD_TAIL(&new_thread->thread, &thread_list, list);
    _DkInternalUnlock(&thread_list_lock);

    int ret = ocall_clone_thread();
    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    *handle = new_thread;
    return 0;
}

int _DkThreadDelayExecution (unsigned long * duration)
{
    int ret = ocall_sleep(duration);
    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : ret;
}

/* PAL call DkThreadYieldExecution. Yield the execution
   of the current thread. */
void _DkThreadYieldExecution (void)
{
    ocall_sleep(NULL);
}

/* _DkThreadExit for internal use: Thread exiting */
noreturn void _DkThreadExit(int* clear_child_tid) {
    struct pal_handle_thread* exiting_thread = GET_ENCLAVE_TLS(thread);

    /* thread is ready to exit, must inform LibOS by erasing clear_child_tid;
     * note that we don't do it now (because this thread still occupies SGX
     * TCS slot) but during handle_thread_reset in assembly code */
    SET_ENCLAVE_TLS(clear_child_tid, clear_child_tid);
    static_assert(sizeof(*clear_child_tid) == 4,  "unexpected clear_child_tid size");

    /* main thread is not part of the thread_list */
    if(exiting_thread != &pal_control.first_thread->thread) {
        _DkInternalLock(&thread_list_lock);
        LISTP_DEL(exiting_thread, &thread_list, list);
        _DkInternalUnlock(&thread_list_lock);
    }

    ocall_exit(0, /*is_exitgroup=*/false);
}

int _DkThreadResume (PAL_HANDLE threadHandle)
{
    int ret = ocall_resume_thread(threadHandle->thread.tcs);
    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : ret;
}

struct handle_ops thread_ops = {
    /* nothing */
};
