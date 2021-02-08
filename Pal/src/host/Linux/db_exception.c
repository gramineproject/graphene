/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 *               2020 Intel Labs
 */

/*
 * This file contains APIs to set up signal handlers.
 */

#include <stddef.h> /* linux/signal.h misses this dependency (for size_t), at least on Ubuntu 16.04.
                     * We must include it ourselves before including linux/signal.h.
                     */

#include <linux/signal.h>

#include "api.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_security.h"
#include "sigset.h"
#include "ucontext.h"

#if defined(__x86_64__)
/* in x86_64 kernels, sigaction is required to have a user-defined restorer */
__asm__(
".align 16\n"
".LSTART_restore_rt:\n"
".type __restore_rt,@function\n"
"__restore_rt:\n"
"movq $" XSTRINGIFY(__NR_rt_sigreturn) ", %rax\n"
"syscall\n"
);

/* workaround for an old GAS (2.27) bug that incorrectly omits relocations when referencing this
 * symbol */
__attribute__((visibility("hidden"))) void __restore_rt(void);
#endif  /* defined(__x86_64__) */

static const int ASYNC_SIGNALS[] = {SIGTERM, SIGCONT};

static int block_signal(int sig, bool block) {
    int how = block ? SIG_BLOCK : SIG_UNBLOCK;

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
    for (size_t i = 0; i < ARRAY_SIZE(ASYNC_SIGNALS); i++)
        __sigaddset((__sigset_t*)&action.sa_mask, ASYNC_SIGNALS[i]);

    int ret = INLINE_SYSCALL(rt_sigaction, 4, sig, &action, NULL, sizeof(__sigset_t));
    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    return block_signal(sig, /*block=*/false);
}

int block_async_signals(bool block) {
    for (size_t i = 0; i < ARRAY_SIZE(ASYNC_SIGNALS); i++) {
        int ret = block_signal(ASYNC_SIGNALS[i], block);
        if (IS_ERR(ret))
            return unix_to_pal_error(ERRNO(ret));
    }
    return 0;
}

static int get_pal_event(int sig) {
    switch (sig) {
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
        case SIGCONT:
            return PAL_EVENT_INTERRUPTED;
        default:
            return -1;
    }
}

/*
 * This function must be reentrant and thread-safe - this includes `upcall` too! Technically,
 * only for cases when the exception arrived while in Graphene code; if signal arrived while in
 * the user app, this function doesn't need to be reentrant and thread-safe.
 */
static void perform_signal_handling(int event, bool is_in_pal, PAL_NUM addr, ucontext_t* uc) {
    PAL_EVENT_HANDLER upcall = _DkGetExceptionHandler(event);
    if (!upcall)
        return;

    PAL_CONTEXT context;
    ucontext_to_pal_context(&context, uc);
    (*upcall)(is_in_pal, addr, &context);
    pal_context_to_ucontext(uc, &context);
}

static void handle_sync_signal(int signum, siginfo_t* info, struct ucontext* uc) {
    int event = get_pal_event(signum);
    assert(event > 0);

    uintptr_t rip = ucontext_get_ip(uc);
    if (!ADDR_IN_PAL(rip)) {
        /* exception happened in application or LibOS code, normal benign case */
        perform_signal_handling(event, /*is_in_pal=*/false, (PAL_NUM)info->si_addr, uc);
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
           name, INLINE_SYSCALL(getpid, 0), INLINE_SYSCALL(gettid, 0), rip - (uintptr_t)TEXT_START);

    _DkProcessExit(1);
    return;
}

static void handle_async_signal(int signum, siginfo_t* info, struct ucontext* uc) {
    __UNUSED(info);

    int event = get_pal_event(signum);
    assert(event > 0);

    uintptr_t rip = ucontext_get_ip(uc);
    perform_signal_handling(event, ADDR_IN_PAL(rip), /*addr=*/0, uc);
}

/* TODO: remove this function. It's not an exception handling, it's just returning an error from
 * PAL... */
void _DkRaiseFailure(int error) {
    PAL_EVENT_HANDLER upcall = _DkGetExceptionHandler(PAL_EVENT_FAILURE);
    if (upcall) {
        (*upcall)(/*is_in_pal=*/false, error, /*context=*/NULL);
    }
}

void signal_setup(void) {
    int ret;

    /* SIGPIPE and SIGCHLD are emulated completely inside LibOS */
    ret = set_signal_handler(SIGPIPE, SIG_IGN);
    if (ret < 0)
        goto err;

    ret = set_signal_handler(SIGCHLD, SIG_IGN);
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
    for (size_t i = 0; i < ARRAY_SIZE(ASYNC_SIGNALS); i++) {
        ret = set_signal_handler(ASYNC_SIGNALS[i], handle_async_signal);
        if (ret < 0)
            goto err;
    }

    return;
err:
    INIT_FAIL(-ret, "Cannot setup signal handlers!");
}
