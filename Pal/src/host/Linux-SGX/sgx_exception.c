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

#include "sigset.h" /* FIXME: this include can't be sorted, otherwise we get:
                     * In file included from sgx_exception.c:19:0:
                     * ../../../include/arch/x86_64/Linux/ucontext.h:136:5: error: unknown type name ‘__sigset_t’
                     *      __sigset_t uc_sigmask;
                     */


#include <asm/errno.h>
#include <linux/signal.h>
#include <stdbool.h>

#include "api.h"
#include "ecall_types.h"
#include "ocall_types.h"
#include "pal_linux.h"
#include "rpc_queue.h"
#include "sgx_enclave.h"
#include "sgx_internal.h"
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
#endif /* defined(__x86_64__) */

void sgx_entry_return(void);

static const int ASYNC_SIGNALS[] = {SIGTERM, SIGINT, SIGCONT};

static int block_signal(int sig, bool block) {
    int how = block ? SIG_BLOCK : SIG_UNBLOCK;

    __sigset_t mask;
    __sigemptyset(&mask);
    __sigaddset(&mask, sig);

    int ret = INLINE_SYSCALL(rt_sigprocmask, 4, how, &mask, NULL, sizeof(__sigset_t));
    return IS_ERR(ret) ? -ERRNO(ret) : 0;
}

static int set_signal_handler(int sig, void* handler) {
    struct sigaction action = {0};
    action.sa_handler  = handler;
    action.sa_flags    = SA_SIGINFO | SA_ONSTACK | SA_RESTORER;
    action.sa_restorer = __restore_rt;

    /* disallow nested asynchronous signals during enclave exception handling */
    __sigemptyset((__sigset_t*)&action.sa_mask);
    for (size_t i = 0; i < ARRAY_SIZE(ASYNC_SIGNALS); i++)
        __sigaddset((__sigset_t*)&action.sa_mask, ASYNC_SIGNALS[i]);

    int ret = INLINE_SYSCALL(rt_sigaction, 4, sig, &action, NULL, sizeof(__sigset_t));
    if (IS_ERR(ret))
        return -ERRNO(ret);

    return block_signal(sig, /*block=*/false);
}

int block_async_signals(bool block) {
    for (size_t i = 0; i < ARRAY_SIZE(ASYNC_SIGNALS); i++) {
        int ret = block_signal(ASYNC_SIGNALS[i], block);
        if (IS_ERR(ret))
            return -ERRNO(ret);
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
        case SIGINT:
            return PAL_EVENT_SUSPEND;
        case SIGCONT:
            return PAL_EVENT_RESUME;
        default:
            return -1;
    }
}

static bool interrupted_in_enclave(struct ucontext* uc) {
    unsigned long rip = pal_ucontext_get_ip(uc);

    /* in case of AEX, RIP can point to any instruction in the AEP/ERESUME trampoline code, i.e.,
     * RIP can point to anywhere in [async_exit_pointer, async_exit_pointer_end) interval */
    return rip >= (unsigned long)async_exit_pointer && rip < (unsigned long)async_exit_pointer_end;
}

static void handle_sync_signal(int signum, siginfo_t* info, struct ucontext* uc) {
    int event = get_pal_event(signum);
    assert(event > 0);

    __UNUSED(info);

    /* send dummy signal to RPC threads so they interrupt blocked syscalls */
    if (g_rpc_queue)
        for (size_t i = 0; i < g_rpc_queue->rpc_threads_cnt; i++)
            INLINE_SYSCALL(tkill, 2, g_rpc_queue->rpc_threads[i], SIGUSR2);

    if (interrupted_in_enclave(uc)) {
        /* exception happened in app/LibOS/trusted PAL code, handle signal inside enclave */
        get_tcb_urts()->sync_signal_cnt++;
        sgx_raise(event);
        return;
    }

    /* exception happened in untrusted PAL code (during syscall handling): fatal in Graphene */
    unsigned long rip = pal_ucontext_get_ip(uc);
    switch (signum) {
        case SIGSEGV:
            SGX_DBG(DBG_E, "Segmentation Fault in Untrusted Code (RIP = %08lx)\n", rip);
            break;
        case SIGILL:
            SGX_DBG(DBG_E, "Illegal Instruction in Untrusted Code (RIP = %08lx)\n", rip);
            break;
        case SIGFPE:
            SGX_DBG(DBG_E, "Arithmetic Exception in Untrusted Code (RIP = %08lx)\n", rip);
            break;
        case SIGBUS:
            SGX_DBG(DBG_E, "Memory Mapping Exception in Untrusted Code (RIP = %08lx)\n", rip);
            break;
    }
    INLINE_SYSCALL(exit, 1, 1);
}

static void handle_async_signal(int signum, siginfo_t* info, struct ucontext* uc) {
    int event = get_pal_event(signum);
    assert(event > 0);

    __UNUSED(info);

    /* send dummy signal to RPC threads so they interrupt blocked syscalls */
    if (g_rpc_queue)
        for (size_t i = 0; i < g_rpc_queue->rpc_threads_cnt; i++)
            INLINE_SYSCALL(tkill, 2, g_rpc_queue->rpc_threads[i], SIGUSR2);

    if (interrupted_in_enclave(uc)) {
        /* signal arrived while in app/LibOS/trusted PAL code, handle signal inside enclave */
        get_tcb_urts()->async_signal_cnt++;
        sgx_raise(event);
        return;
    }

    /* signal arrived while in untrusted PAL code (during syscall handling), emulate as if syscall
     * was interrupted by calling sgx_entry_return(syscall_return_value=-EINTR, event) */
    /* TODO: we abandon PAL state here (possibly still holding some locks, etc) and return to
     *       enclave; ideally we must unwind/fix the state and only then jump into enclave */
    greg_t func_args[2] = {-EINTR, event};
    pal_ucontext_set_function_parameters(uc, sgx_entry_return, /*func_args_num=*/2, func_args);
}

static void handle_dummy_signal(int signum, siginfo_t* info, struct ucontext* uc) {
    __UNUSED(signum);
    __UNUSED(info);
    __UNUSED(uc);
    /* we need this handler to interrupt blocking syscalls in RPC threads */
}

int sgx_signal_setup(void) {
    int ret;

    /* SIGCHLD and SIGPIPE are emulated completely inside LibOS */
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

    /* SIGUSR2 is reserved for Graphene usage: interrupting blocking syscalls in RPC threads.
     * We block SIGUSR2 in enclave threads; it is unblocked by each RPC thread explicitly. */
    ret = set_signal_handler(SIGUSR2, handle_dummy_signal);
    if (ret < 0)
        goto err;

    ret = block_signal(SIGUSR2, /*block=*/true);
    if (ret < 0)
        goto err;

    ret = 0;
err:
    return ret;
}
