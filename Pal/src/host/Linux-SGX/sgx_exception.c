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
 * db_signal.c
 *
 * This file contains APIs to set up handlers of exceptions issued by the
 * host, and the methods to pass the exceptions to the upcalls.
 */

#include "api.h"
#include "ecall_types.h"
#include "ocall_types.h"
#include "pal_linux.h"
#include "rpc_queue.h"
#include "sgx_enclave.h"
#include "sgx_internal.h"

#include <asm/errno.h>
#include <atomic.h>
#include <linux/signal.h>
#include <sigset.h>
#include <ucontext.h>

#if !defined(__i386__)
/* In x86_64 kernels, sigaction is required to have a user-defined
 * restorer. Also, they not yet support SA_INFO. The reference:
 * http://lxr.linux.no/linux+v2.6.35/arch/x86/kernel/signal.c#L448
 *
 *     / * x86-64 should always use SA_RESTORER. * /
 *     if (ka->sa.sa_flags & SA_RESTORER) {
 *             put_user_ex(ka->sa.sa_restorer, &frame->pretcode);
 *     } else {
 *             / * could use a vstub here * /
 *             err |= -EFAULT;
 *     }
 */

#ifndef SA_RESTORER
#define SA_RESTORER  0x04000000
#endif

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

/* Workaround for fixing an old GAS (2.27) bug that incorrectly
 * omits relocations when referencing this symbol */
__attribute__((visibility("hidden"))) void __restore_rt(void);

#endif

static const int async_signals[] =
{
    SIGTERM,
    SIGINT,
    SIGCONT,
};

static const int nasync_signals = ARRAY_SIZE(async_signals);

int set_sighandler (int * sigs, int nsig, void * handler)
{
    struct sigaction action;
    action.sa_handler = (void (*)(int)) handler;
    action.sa_flags = SA_SIGINFO;

#if !defined(__i386__)
    action.sa_flags |= SA_RESTORER;
    action.sa_restorer = __restore_rt;
#endif

    /* Disallow nested asynchronous signals during enclave exception handling.
     */
    __sigemptyset((__sigset_t *) &action.sa_mask);
    for (int i = 0; i < nasync_signals; i++)
        __sigaddset((__sigset_t *) &action.sa_mask, async_signals[i]);

    for (int i = 0 ; i < nsig ; i++) {
        if (sigs[i] == SIGCHLD)
            action.sa_flags |= SA_NOCLDSTOP|SA_NOCLDWAIT;

#if defined(__i386__)
        int ret = INLINE_SYSCALL(sigaction, 3, sigs[i], &action, NULL)
#else
        int ret = INLINE_SYSCALL(rt_sigaction, 4, sigs[i], &action, NULL,
                                 sizeof(sigset_t));
#endif
        if (IS_ERR(ret))
            return -ERRNO(ret);

        action.sa_flags &= ~(SA_NOCLDSTOP|SA_NOCLDWAIT);
    }

    int ret = 0;
    __sigset_t mask;
    __sigemptyset(&mask);
    for (int i = 0 ; i < nsig ; i++)
        __sigaddset(&mask, sigs[i]);

#if defined(__i386__)
    ret = INLINE_SYSCALL(sigprocmask, 3, SIG_UNBLOCK, &mask, NULL)
#else
    ret = INLINE_SYSCALL(rt_sigprocmask, 4, SIG_UNBLOCK, &mask, NULL,
                         sizeof(sigset_t));
#endif

    if (IS_ERR(ret))
        return -ERRNO(ret);

    return 0;
}

int block_signals (bool block, const int * sigs, int nsig)
{
    int how = block? SIG_BLOCK: SIG_UNBLOCK;
    int ret = 0;
    __sigset_t mask;
    __sigemptyset(&mask);
    for (int i = 0 ; i < nsig ; i++)
        __sigaddset(&mask, sigs[i]);

#if defined(__i386__)
    ret = INLINE_SYSCALL(sigprocmask, 3, how, &mask, NULL)
#else
    ret = INLINE_SYSCALL(rt_sigprocmask, 4, how, &mask, NULL,
                         sizeof(sigset_t));
#endif

    if (IS_ERR(ret))
        return -ERRNO(ret);

    return 0;
}

int block_async_signals (bool block)
{
    return block_signals(block, async_signals, nasync_signals);
}

static int get_event_num (int signum)
{
    switch(signum) {
        case SIGFPE:                return PAL_EVENT_ARITHMETIC_ERROR;
        case SIGSEGV: case SIGBUS:  return PAL_EVENT_MEMFAULT;
        case SIGILL:                return PAL_EVENT_ILLEGAL;
        case SIGTERM:               return PAL_EVENT_QUIT;
        case SIGINT:                return PAL_EVENT_SUSPEND;
        case SIGCONT:               return PAL_EVENT_RESUME;
        default: return -1;
    }
}

void sgx_entry_return (void);

static void _DkTerminateSighandler (int signum, siginfo_t * info,
                                    struct ucontext * uc)
{
    __UNUSED(info);

    /* send dummy signal to RPC threads so they interrupt blocked syscalls */
    if (g_rpc_queue)
        for (size_t i = 0; i < g_rpc_queue->rpc_threads_cnt; i++)
            INLINE_SYSCALL(tkill, 2, g_rpc_queue->rpc_threads[i], SIGUSR2);

    unsigned long rip = uc->uc_mcontext.gregs[REG_RIP];

    if (rip != (unsigned long) async_exit_pointer) {
        uc->uc_mcontext.gregs[REG_RIP] = (uint64_t) sgx_entry_return;
        uc->uc_mcontext.gregs[REG_RDI] = -EINTR;
        uc->uc_mcontext.gregs[REG_RSI] = get_event_num(signum);
    } else {
        sgx_raise(get_event_num(signum));
    }
}

static void _DkResumeSighandler (int signum, siginfo_t * info,
                                 struct ucontext * uc)
{
    __UNUSED(info);

    /* send dummy signal to RPC threads so they interrupt blocked syscalls */
    if (g_rpc_queue)
        for (size_t i = 0; i < g_rpc_queue->rpc_threads_cnt; i++)
            INLINE_SYSCALL(tkill, 2, g_rpc_queue->rpc_threads[i], SIGUSR2);

    unsigned long rip = uc->uc_mcontext.gregs[REG_RIP];

    if (rip != (unsigned long) async_exit_pointer) {
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

    int event = get_event_num(signum);
    sgx_raise(event);
}

static void _DkEmptySighandler(int signum, siginfo_t* info, struct ucontext* uc) {
    __UNUSED(signum);
    __UNUSED(info);
    __UNUSED(uc);
    /* we need this handler to interrupt blocking syscalls in RPC threads */
}

int sgx_signal_setup (void)
{
    int ret, sig[4];

    sig[0] = SIGTERM;
    sig[1] = SIGINT;
    sig[2] = SIGCONT;
    if ((ret = set_sighandler(sig, 3, &_DkTerminateSighandler)) < 0)
        goto err;

    sig[0] = SIGSEGV;
    sig[1] = SIGILL;
    sig[2] = SIGFPE;
    sig[3] = SIGBUS;
    if ((ret = set_sighandler(sig, 4, &_DkResumeSighandler)) < 0)
        goto err;

    /* SIGUSR2 is reserved for Graphene usage: interrupting blocking syscalls in RPC threads.
     * We block SIGUSR2 in enclave threads; it is unblocked by each RPC thread explicitly. */
    sig[0] = SIGUSR2;
    if ((ret = set_sighandler(sig, 1, &_DkEmptySighandler)) < 0)
        goto err;
    if (block_signals(true, sig, 1) < 0)
        goto err;

    return 0;
err:
    return ret;
}
