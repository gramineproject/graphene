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

#include <errno.h>
#include <linux/signal.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/wait.h>

#if defined(__i386__)
#include <asm/ldt.h>
#else
#include <asm/prctl.h>
#endif

/*
 * pal_thread_init(): An initialization wrapper of a newly-created thread (including
 * the first thread). This function accepts a TCB pointer to be set to the GS register
 * of the thread. The rest of the TCB is used as the alternative stack for signal
 * handling.
 */
int pal_thread_init (void * tcbptr)
{
    PAL_TCB_LINUX * tcb = tcbptr;
    int ret;

    ret = INLINE_SYSCALL(arch_prctl, 2, ARCH_SET_GS, tcb);
    if (IS_ERR(ret))
        return -ERRNO(ret);

    if (tcb->alt_stack) {
        // Align stack to 16 bytes
        void * alt_stack_top = (void *) ((uint64_t) tcb & ~15);
        assert(alt_stack_top > tcb->alt_stack);
        stack_t ss;
        ss.ss_sp    = alt_stack_top;
        ss.ss_flags = 0;
        ss.ss_size  = alt_stack_top - tcb->alt_stack;

        ret = INLINE_SYSCALL(sigaltstack, 2, &ss, NULL);
        if (IS_ERR(ret))
            return -ERRNO(ret);
    }

    if (tcb->callback)
        return (*tcb->callback) (tcb->param);

    return 0;
}

/* _DkThreadCreate for internal use. Create an internal thread
   inside the current process. The arguments callback and param
   specify the starting function and parameters */
int _DkThreadCreate (PAL_HANDLE * handle, int (*callback) (void *),
                     const void * param)
{
    int ret = 0;
    PAL_HANDLE hdl = NULL;
    void * stack = malloc(THREAD_STACK_SIZE + ALT_STACK_SIZE);
    if (!stack) {
        ret = -ENOMEM;
        goto err;
    }
    memset(stack, 0, THREAD_STACK_SIZE + ALT_STACK_SIZE);

    void * child_stack = stack + THREAD_STACK_SIZE;

    hdl = malloc(HANDLE_SIZE(thread));
    if (!hdl) {
        ret = -ENOMEM;
        goto err;
    }
    SET_HANDLE_TYPE(hdl, thread);

    // Initialize TCB at the top of the alternative stack.
    PAL_TCB_LINUX * tcb  = child_stack + ALT_STACK_SIZE - sizeof(PAL_TCB_LINUX);
    tcb->common.self = &tcb->common;
    tcb->handle    = hdl;
    tcb->alt_stack = child_stack; // Stack bottom
    tcb->callback  = callback;
    tcb->param     = (void *) param;

    /* align child_stack to 16 */
    child_stack = ALIGN_DOWN_PTR(child_stack, 16);

    ret = clone(pal_thread_init, child_stack,
                    CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SYSVSEM|
                    CLONE_THREAD|CLONE_SIGHAND|CLONE_PTRACE|
                    CLONE_PARENT_SETTID,
                    (void *) tcb, &hdl->thread.tid, NULL);

    if (IS_ERR(ret)) {
        ret = -PAL_ERROR_DENIED;
        goto err;
    }

    hdl->thread.stack = stack;
    *handle = hdl;
    return 0;
err:
    free(stack);
    free(hdl);
    return ret;
}

int _DkThreadDelayExecution (unsigned long * duration)
{
    struct timespec sleeptime;
    struct timespec remainingtime;

    const unsigned long VERY_LONG_TIME_IN_US = 1000000L * 60 * 60 * 24 * 365 * 128;
    if (*duration > VERY_LONG_TIME_IN_US) {
        /* avoid overflow with time_t */
        sleeptime.tv_sec  = VERY_LONG_TIME_IN_US / 1000000;
        sleeptime.tv_nsec = 0;
    } else {
        sleeptime.tv_sec = *duration / 1000000;
        sleeptime.tv_nsec = (*duration - sleeptime.tv_sec * 1000000) * 1000;
    }

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
noreturn void _DkThreadExit (void)
{
    PAL_TCB_LINUX* tcb = get_tcb_linux();
    PAL_HANDLE handle = tcb->handle;

    block_async_signals(true);
    if (tcb->alt_stack) {
        stack_t ss;
        ss.ss_sp    = NULL;
        ss.ss_flags = SS_DISABLE;
        ss.ss_size  = 0;

        // Take precautions to unset the TCB and alternative stack first.
        INLINE_SYSCALL(arch_prctl, 2, ARCH_SET_GS, 0);
        INLINE_SYSCALL(sigaltstack, 2, &ss, NULL);
    }

    if (handle) {
        // Free the thread stack
        free(handle->thread.stack);
        // After this line, needs to exit the thread immediately
    }

    INLINE_SYSCALL(exit, 1, 0);
    while (true) {
        /* nothing */
    }
}

int _DkThreadResume (PAL_HANDLE threadHandle)
{
    int ret = INLINE_SYSCALL(tgkill, 3,
                             linux_state.pid,
                             threadHandle->thread.tid,
                             SIGCONT);

    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    return 0;
}

struct handle_ops thread_ops = {
    /* nothing */
};
