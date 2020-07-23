/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * db_threading.c
 *
 * This file contain APIs to create, exit and yield a thread.
 */

#include "api.h"
#include "ecall_types.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_linux_error.h"

#include <linux/mman.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/types.h>
#include <linux/wait.h>

#include <list.h>

static PAL_LOCK g_thread_list_lock = LOCK_INIT;
DEFINE_LISTP(pal_handle_thread);
static LISTP_TYPE(pal_handle_thread) g_thread_list = LISTP_INIT;

struct thread_param {
    int (*callback) (void *);
    const void * param;
};

extern void* g_enclave_base;

/*
 * We do not currently handle tid counter wrap-around, and could, in
 * principle, end up with two threads with the same ID. This is ok, as strict
 * uniqueness is not required; the tid is only used for debugging. We could
 * ensure uniqueness if needed in the future
 */
static PAL_IDX pal_assign_tid(void)
{
    static struct atomic_int tid = ATOMIC_INIT(0);
    return __atomic_add_fetch(&tid.counter, 1, __ATOMIC_SEQ_CST);
}

void pal_start_thread (void)
{
    struct pal_handle_thread *new_thread = NULL, *tmp;

    _DkInternalLock(&g_thread_list_lock);
    LISTP_FOR_EACH_ENTRY(tmp, &g_thread_list, list)
        if (!tmp->tcs) {
            new_thread = tmp;
            new_thread->tid = pal_assign_tid();
            new_thread->tcs = g_enclave_base + GET_ENCLAVE_TLS(tcs_offset);
            break;
        }
    _DkInternalUnlock(&g_thread_list_lock);

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
    /* UNREACHABLE */
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

    _DkInternalLock(&g_thread_list_lock);
    LISTP_ADD_TAIL(&new_thread->thread, &g_thread_list, list);
    _DkInternalUnlock(&g_thread_list_lock);

    int ret = ocall_clone_thread();
    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    *handle = new_thread;
    return 0;
}

int _DkThreadDelayExecution(uint64_t* duration_us) {
    int ret = ocall_sleep(duration_us);
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

    /* main thread is not part of the g_thread_list */
    if(exiting_thread != &pal_control.first_thread->thread) {
        _DkInternalLock(&g_thread_list_lock);
        LISTP_DEL(exiting_thread, &g_thread_list, list);
        _DkInternalUnlock(&g_thread_list_lock);
    }

    ocall_exit(0, /*is_exitgroup=*/false);
}

int _DkThreadResume (PAL_HANDLE threadHandle)
{
    int ret = ocall_resume_thread(threadHandle->thread.tcs);
    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : ret;
}

struct handle_ops g_thread_ops = {
    /* nothing */
};
