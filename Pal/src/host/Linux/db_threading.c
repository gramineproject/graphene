/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * db_threading.c
 *
 * This file contain APIs to create, exit and yield a thread.
 */

#include "api.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "spinlock.h"
#include <errno.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/types.h>
#include <linux/wait.h>

/* Linux PAL cannot use mmap/unmap to manage thread stacks because this may overlap with
 * pal_control.user_address. Linux PAL also cannot just use malloc/free because DkThreadExit
 * needs to use raw system calls and inline asm. Thus, we resort to recycling thread stacks
 * allocated by previous threads and not used anymore. This still leaks memory but at least
 * it is bounded by the maximum number of simultaneously executing threads. Note that main
 * thread is not a part of this mechanism (it only allocates a tiny altstack). */
struct thread_stack_map_t {
    void* stack;
    bool  used;
};

static struct thread_stack_map_t* g_thread_stack_map = NULL;
static size_t g_thread_stack_num  = 0;
static size_t g_thread_stack_size = 0;
static spinlock_t g_thread_stack_lock = INIT_SPINLOCK_UNLOCKED;

static void* get_thread_stack(void) {
    void* ret = NULL;
    spinlock_lock(&g_thread_stack_lock);
    for (size_t i = 0; i < g_thread_stack_num; i++) {
        if (!g_thread_stack_map[i].used) {
            /* found allocated and unused stack -- use it */
            g_thread_stack_map[i].used = true;
            ret = g_thread_stack_map[i].stack;
            goto out;
        }
    }

    if (g_thread_stack_num == g_thread_stack_size) {
        /* realloc g_thread_stack_map to accommodate more objects (includes the very first time) */
        g_thread_stack_size += 8;
        struct thread_stack_map_t* tmp = malloc(g_thread_stack_size * sizeof(*tmp));
        if (!tmp)
            goto out;

        memcpy(tmp, g_thread_stack_map, g_thread_stack_num * sizeof(*tmp));
        free(g_thread_stack_map);
        g_thread_stack_map = tmp;
    }

    ret = malloc(THREAD_STACK_SIZE + ALT_STACK_SIZE);
    if (!ret)
        goto out;

    g_thread_stack_map[g_thread_stack_num].stack = ret;
    g_thread_stack_map[g_thread_stack_num].used  = true;
    g_thread_stack_num++;
out:
    spinlock_unlock(&g_thread_stack_lock);
    return ret;
}

/*
 * pal_thread_init(): An initialization wrapper of a newly-created thread (including
 * the first thread). This function accepts a TCB pointer to be set to the GS register
 * of the thread. The rest of the TCB is used as the alternative stack for signal
 * handling.
 */
int pal_thread_init(void* tcbptr) {
    PAL_TCB_LINUX* tcb = tcbptr;
    int ret;

    ret = pal_set_tcb(&tcb->common);
    if (IS_ERR(ret))
        return -ERRNO(ret);

    if (tcb->alt_stack) {
        stack_t ss = {
            .ss_sp    = tcb->alt_stack,
            .ss_flags = 0,
            .ss_size  = ALT_STACK_SIZE - sizeof(*tcb),
        };

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
    void* stack = get_thread_stack();
    if (!stack) {
        ret = -ENOMEM;
        goto err;
    }

    /* Stack layout for the new thread looks like this (recall that stacks grow towards lower
     * addresses on Linux on x86-64):
     *
     *       stack +--> +-------------------+
     *                  |  child stack      | THREAD_STACK_SIZE
     * child_stack +--> +-------------------+
     *                  |  alternate stack  | ALT_STACK_SIZE - sizeof(PAL_TCB_LINUX)
     *         tcb +--> +-------------------+
     *                  |  PAL TCB          | sizeof(PAL_TCB_LINUX)
     *                  +-------------------+
     *
     * We zero out only the first page of the main stack (to comply with the requirement of
     * gcc ABI, in particular that the initial stack frame's return address must be NULL).
     * We zero out the whole altstack (since it is small anyway) and also the PAL TCB. */
    memset(stack + THREAD_STACK_SIZE - PRESET_PAGESIZE, 0, PRESET_PAGESIZE);
    memset(stack + THREAD_STACK_SIZE, 0, ALT_STACK_SIZE);

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
                CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SYSVSEM | CLONE_THREAD |
                CLONE_SIGHAND | CLONE_PARENT_SETTID,
                (void*)tcb, &hdl->thread.tid, NULL);

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

int _DkThreadDelayExecution(uint64_t* duration_us) {
    struct timespec sleeptime;
    struct timespec remainingtime;

    const uint64_t VERY_LONG_TIME_IN_US = (uint64_t)1000000 * 60 * 60 * 24 * 365 * 128;
    if (*duration_us > VERY_LONG_TIME_IN_US) {
        /* avoid overflow with time_t */
        sleeptime.tv_sec  = VERY_LONG_TIME_IN_US / 1000000;
        sleeptime.tv_nsec = 0;
    } else {
        sleeptime.tv_sec = *duration_us / 1000000;
        sleeptime.tv_nsec = (*duration_us - sleeptime.tv_sec * (uint64_t)1000000) * 1000;
    }

    int ret = INLINE_SYSCALL(nanosleep, 2, &sleeptime, &remainingtime);

    if (IS_ERR(ret)) {
        PAL_NUM remaining = remainingtime.tv_sec * 1000000 + remainingtime.tv_nsec / 1000;
        *duration_us -= remaining;
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
noreturn void _DkThreadExit(int* clear_child_tid) {
    PAL_TCB_LINUX* tcb = get_tcb_linux();
    PAL_HANDLE handle = tcb->handle;
    assert(handle);

    block_async_signals(true);
    if (tcb->alt_stack) {
        stack_t ss;
        ss.ss_sp    = NULL;
        ss.ss_flags = SS_DISABLE;
        ss.ss_size  = 0;

        // Take precautions to unset the TCB and alternative stack first.
        pal_set_tcb(NULL);
        INLINE_SYSCALL(sigaltstack, 2, &ss, NULL);
    }

    /* we do not free thread stack but instead mark it as recycled, see get_thread_stack() */
    spinlock_lock(&g_thread_stack_lock);
    for (size_t i = 0; i < g_thread_stack_num; i++) {
        if (g_thread_stack_map[i].stack == handle->thread.stack) {
            g_thread_stack_map[i].used = false;
            break;
        }
    }
    /* we might still be using the stack we just marked as unused until we enter the asm mode,
     * so we do not unlock now but rather in asm below */

    /* To make sure the compiler doesn't touch the stack after it was freed, need inline asm:
     *   1. Unlock g_thread_stack_lock (so that other threads can start re-using this stack)
     *   2. Set *clear_child_tid = 0 if clear_child_tid != NULL
     *      (we thus inform LibOS, where async helper thread is waiting on this to wake up parent)
     *   3. Exit thread */
    static_assert(sizeof(g_thread_stack_lock.lock) == 4, "unexpected g_thread_stack_lock.lock size");
    static_assert(offsetof(__typeof__(g_thread_stack_lock), lock) == 0, "unexpected offset of lock in g_thread_stack_lock");
    static_assert(sizeof(*clear_child_tid) == 4,  "unexpected clear_child_tid size");

    __asm__ volatile("movl $0, (%%rdx) \n\t"   /* spinlock_unlock(&g_thread_stack_lock) */
                     "cmpq $0, %%rbx \n\t"     /* check if clear_child_tid != NULL */
                     "je 1f \n\t"
                     "movl $0, (%%rbx) \n\t"   /* set *clear_child_tid = 0 */
                     "1: \n\t"
                     "syscall \n\t"            /* rdi arg is already prepared, call exit */
                     : /* no output regs since we don't return from exit */
                     : "a"(__NR_exit), "D"(0), /* rdi = exit status == 0 */
                       "d"(&g_thread_stack_lock.lock), "b"(clear_child_tid)
                     : "cc", "rcx", "r11", "memory"  /* syscall instr clobbers cc, rcx, and r11 */
    );

    while (true) {
        /* nothing */
    }
}

int _DkThreadResume (PAL_HANDLE threadHandle)
{
    int ret = INLINE_SYSCALL(tgkill, 3,
                             g_linux_state.pid,
                             threadHandle->thread.tid,
                             SIGCONT);

    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    return 0;
}

struct handle_ops g_thread_ops = {
    /* nothing */
};
