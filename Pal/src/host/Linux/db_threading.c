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
    PAL_TCB * tcb = tcbptr;
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
                     const void * param, int flags)
{
    void * stack = NULL;
    int ret = _DkVirtualMemoryAlloc(&stack, THREAD_STACK_SIZE + ALT_STACK_SIZE,
                                    0, PAL_PROT_READ|PAL_PROT_WRITE);
    if (ret < 0)
        return ret;

    void * child_stack = stack + THREAD_STACK_SIZE;

    PAL_HANDLE hdl = malloc(HANDLE_SIZE(thread));
    if (!hdl) {
        ret = -ENOMEM;
        goto err;
    }
    SET_HANDLE_TYPE(hdl, thread);

    // Initialize TCB at the top of the alternative stack.
    PAL_TCB * tcb  = child_stack + ALT_STACK_SIZE - sizeof(PAL_TCB);
    tcb->self      = tcb;
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
    if (stack)
        _DkVirtualMemoryFree(stack, THREAD_STACK_SIZE + ALT_STACK_SIZE);
    if (hdl)
        free(hdl);
    return ret;
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
    PAL_TCB* tcb = get_tcb();
    PAL_HANDLE handle = tcb->handle;

    if (tcb->alt_stack) {
        stack_t ss;
        ss.ss_sp    = NULL;
        ss.ss_flags = SS_DISABLE;
        ss.ss_size  = 0;

        // Take precautions to unset the TCB and alternative stack first.
        INLINE_SYSCALL(arch_prctl, 2, ARCH_SET_GS, 0);
        INLINE_SYSCALL(sigaltstack, 2, &ss, NULL);
        INLINE_SYSCALL(munmap, 2, tcb->alt_stack, ALT_STACK_SIZE);
    }

    if (handle && handle->thread.stack) {
        // Free the thread stack
        INLINE_SYSCALL(munmap, 2, handle->thread.stack, THREAD_STACK_SIZE);
        // After this line, needs to exit the thread immediately
    }

    INLINE_SYSCALL(exit, 1, 0);
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
