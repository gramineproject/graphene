/* Copyright (C) 2014 Stony Brook University
                 2020 Intel Labs
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
 * db_exception.c
 *
 * This file contains APIs to set up signal handlers.
 */

#include "api.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_security.h"

#include <linux/signal.h>
#include <sigset.h>
#include <ucontext.h>

#if defined(__x86_64__)
/* in x86_64 kernels, sigaction is required to have a user-defined restorer */
#define DEFINE_RESTORE_RT(syscall) DEFINE_RESTORE_RT2(syscall)
#define DEFINE_RESTORE_RT2(syscall)                 \
    __asm__ (                                       \
         "    nop\n"                                \
         ".align 16\n"                              \
         ".LSTART_restore_rt:\n"                    \
         "    .type __restore_rt,@function\n"       \
         "__restore_rt:\n"                          \
         "    movq $" #syscall ", %rax\n"           \
         "    syscall\n");
DEFINE_RESTORE_RT(__NR_rt_sigreturn)

/* workaround for an old GAS (2.27) bug that incorrectly omits relocations when referencing this
 * symbol */
__attribute__((visibility("hidden"))) void __restore_rt(void);
#endif  /* defined(__x86_64__) */

static const int async_signals[] = {SIGTERM, SIGINT, SIGCONT};

static int block_signal(int sig, bool block) {
    int how = block? SIG_BLOCK: SIG_UNBLOCK;

    __sigset_t mask;
    __sigemptyset(&mask);
    __sigaddset(&mask, sig);

    int ret = INLINE_SYSCALL(rt_sigprocmask, 4, how, &mask, NULL, sizeof(__sigset_t));
    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : 0;
}

static int set_signal_handler(int sig, void* handler) {
    struct sigaction action = {0};
    action.sa_handler  = handler;
    action.sa_flags    = SA_SIGINFO | SA_ONSTACK | SA_RESTORER;
    action.sa_restorer = __restore_rt;

    /* disallow nested asynchronous signals during exception handling */
    __sigemptyset((__sigset_t*)&action.sa_mask);
    for (size_t i = 0; i < ARRAY_SIZE(async_signals); i++)
        __sigaddset((__sigset_t*)&action.sa_mask, async_signals[i]);

    int ret = INLINE_SYSCALL(rt_sigaction, 4, sig, &action, NULL, sizeof(__sigset_t));
    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    return block_signal(sig, /*block=*/false);
}

int block_async_signals(bool block) {
    for (size_t i = 0; i < ARRAY_SIZE(async_signals); i++) {
        int ret = block_signal(async_signals[i], block);
        if (IS_ERR(ret))
            return unix_to_pal_error(ERRNO(ret));
    }
    return 0;
}

static int get_pal_event(int sig) {
    switch(sig) {
        case SIGFPE:
            return PAL_EVENT_ARITHMETIC_ERROR;
        case SIGSEGV:
        case SIGBUS:
            return PAL_EVENT_MEMFAULT;
        case SIGILL:
        case SIGSYS:
            return PAL_EVENT_ILLEGAL;
        case SIGTERM:
            return PAL_EVENT_QUIT;
        case SIGINT:
            return PAL_EVENT_SUSPEND;
        case SIGCONT:
            return PAL_EVENT_RESUME;
        default:
            return -1;
    }
}

static void perform_signal_handling(int event, siginfo_t* info, ucontext_t* uc) {
    PAL_EVENT_HANDLER upcall = _DkGetExceptionHandler(event);
    if (!upcall)
        return;

    PAL_NUM arg = 0;
    if (info) {
        switch (event) {
            case PAL_EVENT_ARITHMETIC_ERROR:
            case PAL_EVENT_MEMFAULT:
            case PAL_EVENT_ILLEGAL:
                arg = (PAL_NUM)info->si_addr;
                break;
        }
    }

    PAL_CONTEXT context;
    ucontext_to_pal_context(&context, uc);
    (*upcall)(/*event=*/NULL, arg, &context);
    pal_context_to_ucontext(uc, &context);
}

static void handle_sync_signal(int signum, siginfo_t* info, struct ucontext* uc) {
    int event = get_pal_event(signum);
    assert(event > 0);

    uintptr_t rip = uc->uc_mcontext.gregs[REG_RIP];
    if (!ADDR_IN_PAL(rip)) {
        /* exception happened in application or LibOS code, normal benign case */
        perform_signal_handling(event, info, uc);
        return;
    }

    /* exception happened in PAL code: this is fatal in Graphene */
    const char* name = "exception";
    switch (event) {
        case PAL_EVENT_ARITHMETIC_ERROR:
            name = "arithmetic exception";
            break;
        case PAL_EVENT_MEMFAULT:
            name = "memory fault";
            break;
        case PAL_EVENT_ILLEGAL:
            name = "illegal instruction";
            break;
    }

    printf("*** Unexpected %s occurred inside PAL (PID = %ld, TID = %ld, RIP = +0x%08lx)! ***\n",
           name, INLINE_SYSCALL(getpid, 0), INLINE_SYSCALL(gettid, 0),
           rip - (uintptr_t)TEXT_START);

    _DkProcessExit(1);
    return;
}

static void handle_async_signal(int signum, siginfo_t* info, struct ucontext* uc) {
    int event = get_pal_event(signum);
    assert(event > 0);

    uintptr_t rip = uc->uc_mcontext.gregs[REG_RIP];

    if (!ADDR_IN_PAL(rip)) {
        /* signal arrived while in application or LibOS code, normal benign case */
        perform_signal_handling(event, info, uc);
        return;
    }

    /* signal arrived while in PAL code, add as pending for this thread; note that there is no race
     * on pending_events as TCB is thread-local and async signals are blocked during signal
     * handling */
    PAL_TCB_LINUX* tcb = get_tcb_linux();
    assert(tcb);
    if (tcb->pending_events_num < MAX_SIGNAL_LOG)
        tcb->pending_events[tcb->pending_events_num++] = event;
}

void __check_pending_event(void) {
    PAL_TCB_LINUX* tcb = get_tcb_linux();
    assert(tcb);

    if (!tcb->pending_events_num)
        return;

    /* block signals while delivering pending events to avoid races on pending_events */
    int ret = block_async_signals(/*block=*/true);
    if (IS_ERR(ret))
        return;

    for (int i = 0; i < tcb->pending_events_num; i++) {
        PAL_EVENT_HANDLER upcall = _DkGetExceptionHandler(tcb->pending_events[i]);
        if (upcall) {
            (*upcall)(/*event=*/NULL, /*arg=*/0, /*context=*/NULL);
        }
    }
    tcb->pending_events_num = 0;

    (void)block_async_signals(/*block=*/false);
}

void _DkRaiseFailure(int error) {
    PAL_EVENT_HANDLER upcall = _DkGetExceptionHandler(PAL_EVENT_FAILURE);
    if (upcall) {
        (*upcall)(/*event=*/NULL, error, /*context=*/NULL);
    }
}

void _DkExceptionReturn(void* event) {
    __UNUSED(event);
}

void signal_setup(void) {
    int ret;

    /* SIGPIPE and SIGCHLD are emulated completely inside LibOS */
    ret = set_signal_handler(SIGPIPE, SIG_IGN);
    if (ret < 0)
        goto err;

    /* Even though SIG_DFL defaults to "ignore", this is not the same as SIG_IGN; man waitpid says:
     * "...if the disposition of SIGCHLD is set to SIG_IGN ..., then children that terminate do not
     * become zombies". In other words, if we would set_signal_handler(SIGCHLD, SIG_IGN) here,
     * children would not become zombies and would die before the parent checks their status. */
    ret = set_signal_handler(SIGCHLD, SIG_DFL);
    if (ret < 0)
        goto err;

    /* register synchronous signals (exceptions) in host Linux */
    ret = set_signal_handler(SIGFPE, handle_sync_signal);
    if (ret < 0)
        goto err;

    ret = set_signal_handler(SIGSEGV, handle_sync_signal);
    if (ret < 0)
        goto err;

    ret = set_signal_handler(SIGBUS, handle_sync_signal);
    if (ret < 0)
        goto err;

    ret = set_signal_handler(SIGILL, handle_sync_signal);
    if (ret < 0)
        goto err;

    ret = set_signal_handler(SIGSYS, handle_sync_signal);
    if (ret < 0)
        goto err;

    /* register asynchronous signals in host Linux */
    ret = set_signal_handler(SIGTERM, handle_async_signal);
    if (ret < 0)
        goto err;

    ret = set_signal_handler(SIGINT, handle_async_signal);
    if (ret < 0)
        goto err;

    ret = set_signal_handler(SIGCONT, handle_async_signal);
    if (ret < 0)
        goto err;

    return;
err:
    INIT_FAIL(-ret, "Cannot setup signal handlers!");
}
