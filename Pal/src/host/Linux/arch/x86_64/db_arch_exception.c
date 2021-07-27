/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 *               2020 Intel Labs
 */

#include <stddef.h> /* needed by <linux/signal.h> for size_t */
#include <linux/signal.h>

#include "sigset.h"
#include "syscall.h"
#include "ucontext.h"

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

int arch_do_rt_sigprocmask(int sig, int how) {
    __sigset_t mask;
    __sigemptyset(&mask);
    __sigaddset(&mask, sig);

    return DO_SYSCALL(rt_sigprocmask, how, &mask, NULL, sizeof(__sigset_t));
}

int arch_do_rt_sigaction(int sig, void* handler,
                         const int* async_signals, size_t num_async_signals) {
    struct sigaction action = {0};
    action.sa_handler  = handler;
    action.sa_flags    = SA_SIGINFO | SA_ONSTACK | SA_RESTORER;
    action.sa_restorer = __restore_rt;

    /* disallow nested asynchronous signals during exception handling */
    __sigemptyset((__sigset_t*)&action.sa_mask);
    for (size_t i = 0; i < num_async_signals; i++)
        __sigaddset((__sigset_t*)&action.sa_mask, async_signals[i]);

    return DO_SYSCALL(rt_sigaction, sig, &action, NULL, sizeof(__sigset_t));
}
