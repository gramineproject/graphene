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
 * db_signal.c
 *
 * This file contains APIs to set up handlers of exceptions issued by the
 * host, and the methods to pass the exceptions to the upcalls.
 */

#include "pal_linux.h"
#include "api.h"
#include "ecall_types.h"
#include "ocall_types.h"
#include "sgx_internal.h"

#include <atomic.h>
#include <sigset.h>
#include <linux/signal.h>
#include <ucontext.h>
#include <asm/errno.h>

#include "sgx_enclave.h"

#define IS_ERR INTERNAL_SYSCALL_ERROR
#define IS_ERR_P INTERNAL_SYSCALL_ERROR_P
#define ERRNO INTERNAL_SYSCALL_ERRNO
#define ERRNO_P INTERNAL_SYSCALL_ERRNO_P

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

void restore_rt (void) asm ("__restore_rt");

#ifndef SA_RESTORER
#define SA_RESTORER  0x04000000
#endif

#define DEFINE_RESTORE_RT(syscall) DEFINE_RESTORE_RT2(syscall)
# define DEFINE_RESTORE_RT2(syscall)                \
    asm (                                           \
         "    nop\n"                                \
         ".align 16\n"                              \
         ".LSTART_restore_rt:\n"                    \
         "    .type __restore_rt,@function\n"       \
         "__restore_rt:\n"                          \
         "    movq $" #syscall ", %rax\n"           \
         "    syscall\n");

DEFINE_RESTORE_RT(__NR_rt_sigreturn)
#endif

int set_sighandler (int * sigs, int nsig, void * handler)
{
    struct sigaction action;
    action.sa_handler = (void (*)(int)) handler;
    action.sa_flags = SA_SIGINFO;

#if !defined(__i386__)
    action.sa_flags |= SA_RESTORER;
    action.sa_restorer = restore_rt;
#endif

    __sigemptyset((__sigset_t *) &action.sa_mask);
    __sigaddset((__sigset_t *) &action.sa_mask, SIGCONT);

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

int block_signals (int * sigs, int nsig)
{
    int ret = 0;
    __sigset_t mask;
    __sigemptyset(&mask);
    for (int i = 0 ; i < nsig ; i++)
        __sigaddset(&mask, sigs[i]);

#if defined(__i386__)
    ret = INLINE_SYSCALL(sigprocmask, 3, SIG_BLOCK, &mask, NULL)
#else
    ret = INLINE_SYSCALL(rt_sigprocmask, 4, SIG_BLOCK, &mask, NULL,
                         sizeof(sigset_t));
#endif

    if (IS_ERR(ret))
        return -ERRNO(ret);

    return 0;
}

int unblock_signals (int * sigs, int nsig)
{
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

int unset_sighandler (int * sigs, int nsig)
{
    for (int i = 0 ; i < nsig ; i++) {
#if defined(__i386__)
        int ret = INLINE_SYSCALL(sigaction, 4, sigs[i], SIG_DFL, NULL)
#else
        int ret = INLINE_SYSCALL(rt_sigaction, 4, sigs[i],
                                 (struct sigaction *) SIG_DFL, NULL,
                                 sizeof(__sigset_t));
#endif
        if (IS_ERR(ret))
            return -ERRNO(ret);
    }
    return 0;
}

static int get_event_num (int signum)
{
    switch(signum) {
        case SIGFPE:                return PAL_EVENT_DIVZERO;
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
    unsigned long rip = uc->uc_mcontext.gregs[REG_RIP];

#if SGX_HAS_FSGSBASE == 0
    if (rip != (unsigned long) async_exit_pointer &&
        rip != (unsigned long) double_async_exit) {
#else
    if (rip != (unsigned long) async_exit_pointer) {
#endif
        uc->uc_mcontext.gregs[REG_RIP] = (uint64_t) sgx_entry_return;
        uc->uc_mcontext.gregs[REG_RDI] = -PAL_ERROR_INTERRUPTED;
        uc->uc_mcontext.gregs[REG_RSI] = get_event_num(signum);
    } else {
#if SGX_HAS_FSGSBASE != 0
        sgx_raise(get_event_num(signum));
#else
        uc->uc_mcontext.gregs[REG_R9]  = get_event_num(signum);
#endif
    }
}

static void _DkResumeSighandler (int signum, siginfo_t * info,
                                 struct ucontext * uc)
{
    unsigned long rip = uc->uc_mcontext.gregs[REG_RIP];

#if SGX_HAS_FSGSBASE == 0
    if (rip != (unsigned long) async_exit_pointer &&
        rip != (unsigned long) double_async_exit) {
#else
    if (rip != (unsigned long) async_exit_pointer) {
#endif
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

    int event = 0;
    switch(signum) {
        case SIGBUS:
        case SIGSEGV:
            event = PAL_EVENT_MEMFAULT;
            break;
        case SIGILL:
            event = PAL_EVENT_ILLEGAL;
            break;
    }
#if SGX_HAS_FSGSBASE != 0
    sgx_raise(event);
#else
    uc->uc_mcontext.gregs[REG_R9] = event;
#endif
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

    return 0;
err:
    return ret;
}
