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
#include "ecall_types.h"
#include "ocall_types.h"
#include "pal_linux.h"
#include "rpc_queue.h"
#include "sgx_enclave.h"
#include "sgx_internal.h"

#include <asm/errno.h>
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

void sgx_entry_return(void);

static const int async_signals[] = {SIGTERM, SIGINT, SIGCONT};

static int block_signal(int sig, bool block) {
    int how = block? SIG_BLOCK: SIG_UNBLOCK;

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
    for (size_t i = 0; i < ARRAY_SIZE(async_signals); i++)
        __sigaddset((__sigset_t*)&action.sa_mask, async_signals[i]);

    int ret = INLINE_SYSCALL(rt_sigaction, 4, sig, &action, NULL, sizeof(__sigset_t));
    if (IS_ERR(ret))
        return -ERRNO(ret);

    return block_signal(sig, /*block=*/false);
}

int block_async_signals(bool block) {
    for (size_t i = 0; i < ARRAY_SIZE(async_signals); i++) {
        int ret = block_signal(async_signals[i], block);
        if (IS_ERR(ret))
            return -ERRNO(ret);
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

static void handle_sync_signal(int signum, siginfo_t* info, struct ucontext* uc) {
    int event = get_pal_event(signum);
    assert(event > 0);

    __UNUSED(info);

    /* send dummy signal to RPC threads so they interrupt blocked syscalls */
    if (g_rpc_queue)
        for (size_t i = 0; i < g_rpc_queue->rpc_threads_cnt; i++)
            INLINE_SYSCALL(tkill, 2, g_rpc_queue->rpc_threads[i], SIGUSR2);

    unsigned long rip = pal_ucontext_get_ip(uc);

    if (rip != (unsigned long)async_exit_pointer) {
        /* exception happened in untrusted PAL code (during syscall handling): fatal in Graphene */
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

    sgx_raise(event);
}

static void handle_async_signal(int signum, siginfo_t* info, struct ucontext* uc) {
    int event = get_pal_event(signum);
    assert(event > 0);

    __UNUSED(info);

    /* send dummy signal to RPC threads so they interrupt blocked syscalls */
    if (g_rpc_queue)
        for (size_t i = 0; i < g_rpc_queue->rpc_threads_cnt; i++)
            INLINE_SYSCALL(tkill, 2, g_rpc_queue->rpc_threads[i], SIGUSR2);

    unsigned long rip = pal_ucontext_get_ip(uc);

    if (rip != (unsigned long)async_exit_pointer) {
        /* signal arrived while in untrusted PAL code (during syscall handling), emulate as if
         * syscall was interrupted */
        pal_ucontext_set_function_parameters(uc, sgx_entry_return, 2, -EINTR, event);
    } else {
        /* signal arrived while in app/LibOS/trusted PAL code, handle signal inside enclave */
        sgx_raise(event);
    }
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
