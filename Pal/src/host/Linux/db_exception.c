/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2014 OSCAR lab, Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * db_signal.c
 *
 * This file contains APIs to set up handlers of exceptions issued by the
 * host, and the methods to pass the exceptions to the upcalls.
 */

#include "pal_defs.h"
#include "pal_linux_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_error.h"
#include "pal_security.h"
#include "api.h"
#include "linux_list.h"

#include <atomic.h>
#include <sigset.h>
#include <linux/signal.h>
#include <ucontext.h>
#include <asm-errno.h>

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
            return -PAL_ERROR_DENIED;

        action.sa_flags &= ~(SA_NOCLDSTOP|SA_NOCLDWAIT);
    }

    bool maskset = false;
    int ret = 0;
    __sigset_t mask;
    __sigemptyset(&mask);
    for (int i = 0 ; i < nsig ; i++)
        if (__sigismember(&pal_linux_config.sigset, sigs[i])) {
            __sigdelset(&pal_linux_config.sigset, sigs[i]);
            __sigaddset(&mask, sigs[i]);
            maskset = true;
        }

    if (maskset) {
#if defined(__i386__)
        ret = INLINE_SYSCALL(sigprocmask, 3, SIG_UNBLOCK, &mask, NULL)
#else
        ret = INLINE_SYSCALL(rt_sigprocmask, 4, SIG_UNBLOCK, &mask, NULL,
                             sizeof(sigset_t));
#endif
    }

    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    return 0;
}

int block_signals (int * sigs, int nsig)
{
    bool maskset = false;
    int ret = 0;
    __sigset_t mask;
    __sigemptyset(&mask);
    for (int i = 0 ; i < nsig ; i++)
        if (!__sigismember(&pal_linux_config.sigset, sigs[i])) {
            __sigaddset(&pal_linux_config.sigset, sigs[i]);
            __sigaddset(&mask, sigs[i]);
            maskset = true;
        }

    if (maskset) {
#if defined(__i386__)
        ret = INLINE_SYSCALL(sigprocmask, 3, SIG_BLOCK, &mask, NULL)
#else
        ret = INLINE_SYSCALL(rt_sigprocmask, 4, SIG_BLOCK, &mask, NULL,
                             sizeof(sigset_t));
#endif
    }

    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    return 0;
}

int unblock_signals (int * sigs, int nsig)
{
    bool maskset = false;
    int ret = 0;
    __sigset_t mask;
    __sigemptyset(&mask);
    for (int i = 0 ; i < nsig ; i++)
        if (__sigismember(&pal_linux_config.sigset, sigs[i])) {
            __sigdelset(&pal_linux_config.sigset, sigs[i]);
            __sigaddset(&mask, sigs[i]);
            maskset = true;
        }

    if (maskset) {
#if defined(__i386__)
        ret = INLINE_SYSCALL(sigprocmask, 3, SIG_UNBLOCK, &mask, NULL)
#else
        ret = INLINE_SYSCALL(rt_sigprocmask, 4, SIG_UNBLOCK, &mask, NULL,
                             sizeof(sigset_t));
#endif
    }

    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    return 0;
}

int unset_sighandler (int * sigs, int nsig)
{
    for (int i = 0 ; i < nsig ; i++) {
#if defined(__i386__)
        int ret = INLINE_SYSCALL(sigaction, 4, sigs[i], SIG_DFL, NULL)
#else
        int ret = INLINE_SYSCALL(rt_sigaction, 4, sigs[i], SIG_DFL, NULL,
                                 sizeof(__sigset_t));
#endif
        if (IS_ERR(ret))
            return -PAL_ERROR_DENIED;
    }
    return 0;
}

struct handler {
    struct mutex_handle lock;
    PAL_UPCALL upcall;
    int flags;
} __attribute__((aligned(sizeof(int))));

struct event {
    unsigned long instance;
    int event_num;
    int flags;
    struct pal_frame * frame;
};

#define DECLARE_HANDLER_HEAD(event)                         \
    static struct handler handler_##event =                 \
        {  .lock = MUTEX_HANDLE_INIT,                       \
           .upcall = NULL,                                  \
           .flags = 0, };

DECLARE_HANDLER_HEAD(DivZero);
DECLARE_HANDLER_HEAD(MemFault);
DECLARE_HANDLER_HEAD(Illegal);
DECLARE_HANDLER_HEAD(Quit);
DECLARE_HANDLER_HEAD(Suspend);
DECLARE_HANDLER_HEAD(Resume);
DECLARE_HANDLER_HEAD(Failure);

struct handler * pal_handlers [PAL_EVENT_NUM_BOUND + 1] = {
        NULL, /* reserved */
        &handler_DivZero,
        &handler_MemFault,
        &handler_Illegal,
        &handler_Quit,
        &handler_Suspend,
        &handler_Resume,
        &handler_Failure,
    };

#define SIGNAL_MASK_TIME 1000

#define save_return_point(ptr)                      \
    asm volatile ("leaq 0(%%rip), %%rax\r\n"        \
                  "movq %%rax, %0\r\n"              \
                  : "=b"(ptr) :: "memory", "rax")

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

void _DkGenericEventTrigger (int event_num, PAL_UPCALL upcall, int flags,
                             PAL_NUM arg, struct pal_frame * frame)
{
    struct event event;

    event.event_num = event_num;
    event.instance = pal_sec_info.domain_id;
    event.flags = flags;
    event.frame = frame;

    (*upcall) (&event, arg, frame ? frame->context : NULL);
}

static bool _DkGenericSignalHandle (int event_num, siginfo_t * info,
                                    struct pal_frame * frame)
{
    struct handler * handler = pal_handlers[event_num];

    _DkMutexLock(&handler->lock);
    PAL_UPCALL upcall = handler->upcall;
    int flags = handler->flags;
    _DkMutexUnlock(&handler->lock);

    PAL_NUM arg = 0;

    if (upcall) {
        if (event_num == PAL_EVENT_DIVZERO ||
            event_num == PAL_EVENT_MEMFAULT ||
            event_num == PAL_EVENT_ILLEGAL)
            arg = (PAL_NUM) (info ? info->si_addr : 0);

        _DkGenericEventTrigger(event_num, upcall, flags, arg, frame);
        return true;
    }

    return false;
}

#define ADDR_IN_PAL(addr)               \
        ((void *) (addr) > pal_config.lib_text_start && \
         (void *) (addr) < pal_config.lib_text_end)

static struct pal_frame * get_frame (struct ucontext * uc)
{
    unsigned long rip = uc->uc_mcontext.gregs[REG_RIP];
    unsigned long rbp = uc->uc_mcontext.gregs[REG_RBP];

    if (!ADDR_IN_PAL(rip))
        return NULL;

    while (ADDR_IN_PAL(((unsigned long *) rbp)[1]))
        rbp = *(unsigned long *) rbp;

    struct pal_frame * frame = (struct pal_frame *) rbp - 1;

    for (int i = 0 ; i < 8 ; i++) {
        if (frame->self == frame)
            return frame;

        frame = (struct pal_frame *) ((void *) frame - 8);
    }

    return NULL;
}

static void return_frame (struct pal_frame * frame, int err)
{
    notify_failure(err);
    arch_restore_frame(&frame->arch);
    asm volatile ("leaveq\r\n"
                  "retq\r\n"
                  ::: "memory");
}

static void _DkGenericSighandler (int signum, siginfo_t * info,
                                  struct ucontext * uc)
{
#if 0
    /* reseurrect this code if signal handler if giving segmentation fault */

    if (signum == SIGSEGV) {
        int pid = INLINE_SYSCALL(getpid, 0);
        char msg[24] = "--- SIGSEGV --- [     ]\n";
        msg[17] = '0' + pid / 10000;
        msg[18] = '0' + (pid / 1000) % 10;
        msg[19] = '0' + (pid / 100) % 10;
        msg[20] = '0' + (pid / 10) % 10;
        msg[21] = '0' + pid % 10;
        INLINE_SYSCALL(write, 3, 1, msg, 24);
        bool go = false;
        while (!go);
    }
#endif

    struct pal_frame * frame = get_frame(uc);

    if (frame && frame->func != &_DkGenericSighandler &&
        signum != SIGCONT &&
        signum != SIGINT  &&
        signum != SIGTERM) {
        return_frame(frame, PAL_ERROR_BADADDR);
        return;
    }

    int event_num = get_event_num(signum);
    if (event_num == -1)
        return;

    if (!frame) {
        frame = __alloca(sizeof(struct pal_frame));
        frame->self     = frame;
        frame->func     = &_DkGenericSighandler;
        frame->funcname = "DkGenericSighandler";
        frame->context  = NULL;
        frame->retval   = NULL;
        arch_store_frame(&frame->arch);
    }

    if (uc) {
        frame->context = __alloca(sizeof(PAL_CONTEXT));
        memcpy(frame->context, uc->uc_mcontext.gregs, sizeof(PAL_CONTEXT));
    } else {
        frame->context = NULL;
    }

    _DkGenericSignalHandle(event_num, info, frame);
}

static void _DkTerminateSighandler (int signum, siginfo_t * info,
                                    struct ucontext * uc)
{
    struct pal_frame * frame = get_frame(uc);

    if (!frame) {
        frame = __alloca(sizeof(struct pal_frame));
        frame->self = frame;
        frame->func = &_DkTerminateSighandler;
        frame->funcname = "DkTerminateSighandler";
        frame->context  = NULL;
        frame->retval   = NULL;
        arch_store_frame(&frame->arch);
    }

    if (uc) {
        frame->context = __alloca(sizeof(PAL_CONTEXT));
        memcpy(frame->context, uc->uc_mcontext.gregs, sizeof(PAL_CONTEXT));
    } else {
        frame->context = NULL;
    }

    int event_num = get_event_num(signum);
    if (event_num == -1)
        return;

    if (!_DkGenericSignalHandle(event_num, NULL, frame))
        _DkThreadExit(0);
}

static void _DkPipeSighandler (int signum, siginfo_t * info,
                               struct ucontext * uc)
{
    struct pal_frame * frame = get_frame(uc);
    if (frame)
        return_frame(frame, PAL_ERROR_CONNFAILED);
}

void notify_failure (unsigned long error)
{
    _DkMutexLock(&handler_Failure.lock);
    PAL_UPCALL upcall = handler_Failure.upcall;
    int flags = handler_Failure.flags;
    _DkMutexUnlock(&handler_Failure.lock);

    if (upcall)
        _DkGenericEventTrigger(PAL_EVENT_FAILURE, upcall, flags,
                               error, NULL);
}

struct signal_ops {
    int signum[3];
    void (*handler) (int signum, siginfo_t * info,
                     struct ucontext * uc);
};

struct signal_ops on_signals[PAL_EVENT_NUM_BOUND + 1] = {
        /* reserved    */ { .signum = { 0 }, .handler = NULL },
        /* DivZero     */ { .signum = { SIGFPE, 0 },
                            .handler = _DkGenericSighandler },
        /* MemFault    */ { .signum = { SIGSEGV, SIGBUS, 0 },
                            .handler = _DkGenericSighandler },
        /* Illegal     */ { .signum = { SIGILL, 0 },
                            .handler = _DkGenericSighandler },
        /* Quit        */ { .signum = { SIGTERM, 0, 0 },
                            .handler = _DkTerminateSighandler },
        /* Suspend     */ { .signum = { SIGINT, 0 },
                            .handler = _DkTerminateSighandler },
        /* Resume      */ { .signum = { SIGCONT, 0 },
                            .handler = _DkGenericSighandler },
        /* Failure     */ { .signum = { 0 }, .handler = NULL },
    };

static int _DkPersistentSighandlerSetup (int event_num)
{
    int nsigs, * sigs = on_signals[event_num].signum;
    for (nsigs = 0 ; sigs[nsigs] ; nsigs++);

    void * sighandler = on_signals[event_num].handler;

    int ret = set_sighandler (sigs, nsigs, sighandler);
    if (ret < 0)
        return ret;

    return 0;
}

static int _DkPersistentEventUpcall (int event_num, PAL_UPCALL upcall,
                                     int flags)
{
    struct handler * handler = pal_handlers[event_num];

    _DkMutexLock(&handler->lock);
    handler->upcall = upcall;
    handler->flags = flags;
    _DkMutexUnlock(&handler->lock);

    return _DkPersistentSighandlerSetup(event_num);
}

static int _DkGenericEventUpcall (int event_num, PAL_UPCALL upcall,
                                  int flags)
{
    int nsigs, * sigs = on_signals[event_num].signum;
    for (nsigs = 0 ; sigs[nsigs] ; nsigs++);

    void * sighandler = on_signals[event_num].handler;
    struct handler * handler = pal_handlers[event_num];
    int ret = 0;

    _DkMutexLock(&handler->lock);
    handler->upcall = upcall;
    handler->flags = flags;
    _DkMutexUnlock(&handler->lock);

    if (upcall)
        ret = set_sighandler (sigs, nsigs, sighandler);
    else
        ret = block_signals (sigs, nsigs);

    return ret;
}

static int _DkDummyEventUpcall (int event_num, PAL_UPCALL upcall,
                                int flags)
{
    struct handler * handler = pal_handlers[event_num];

    _DkMutexLock(&handler->lock);
    handler->upcall = upcall;
    handler->flags = flags;
    _DkMutexUnlock(&handler->lock);

    return 0;
}

typedef void (*PAL_UPCALL) (PAL_PTR, PAL_NUM, PAL_CONTEXT *);

int (*_DkExceptionHandlers[PAL_EVENT_NUM_BOUND + 1])
    (int, PAL_UPCALL, int) = {
        /* reserved   */ NULL,
        /* DivZero    */ &_DkPersistentEventUpcall,
        /* MemFault   */ &_DkPersistentEventUpcall,
        /* Illegal    */ &_DkPersistentEventUpcall,
        /* Quit       */ &_DkGenericEventUpcall,
        /* Suspend    */ &_DkGenericEventUpcall,
        /* Resume     */ &_DkGenericEventUpcall,
        /* Failure    */ &_DkDummyEventUpcall,
    };

static void _DkCompatibilitySighandler (int signum, siginfo_t * info,
                                        struct ucontext * uc)
{
    printf("compatibility support: detected an unintercepted system call\n");

    if (!pal_config.syscall_sym_addr)
        _DkProcessExit(-1);

    asm volatile ("movq %6, %%r10\r\n"
                  "movq %7, %%r8\r\n"
                  "movq %8, %%r9\r\n"
                  "callq *%1\r\n"
                  "movq %%rax, %0\r\n"
                  : "=a" (uc->uc_mcontext.gregs[REG_RAX])
                  : "r"(pal_config.syscall_sym_addr),
                    "a" (uc->uc_mcontext.gregs[REG_RAX]),
                    "D" (uc->uc_mcontext.gregs[REG_RDI]),
                    "S" (uc->uc_mcontext.gregs[REG_RSI]),
                    "d" (uc->uc_mcontext.gregs[REG_RDX]),
                    "r" (uc->uc_mcontext.gregs[REG_R10]),
                    "r" (uc->uc_mcontext.gregs[REG_R8]),
                    "r" (uc->uc_mcontext.gregs[REG_R9])
                  : "memory", "r10", "r8", "r9");
}

int signal_setup (void)
{
    int ret, sig;
    __sigemptyset(&pal_linux_config.sigset);

    if ((ret = _DkPersistentEventUpcall(PAL_EVENT_DIVZERO,  NULL, 0)) < 0)
        goto err;

    if ((ret = _DkPersistentEventUpcall(PAL_EVENT_MEMFAULT,  NULL, 0)) < 0)
        goto err;

    if ((ret = _DkPersistentEventUpcall(PAL_EVENT_ILLEGAL,  NULL, 0)) < 0)
        goto err;

    sig = SIGPIPE;
    if ((ret = set_sighandler(&sig, 1, &_DkPipeSighandler)) < 0)
        goto err;

    sig = SIGSYS;
    if ((ret = set_sighandler(&sig, 1, &_DkCompatibilitySighandler)) < 0)
        goto err;

    return 0;

err:
    return ret;
}

void _DkExceptionReturn (const void * event)
{
    const struct event * e = (const struct event *) event;

    if (e->instance == pal_sec_info.domain_id)
        return;

    int event_n = e->event_num;

    if (event_n > 0 && event_n <= PAL_EVENT_NUM_BOUND) {
        arch_restore_frame(&e->frame->arch);
        asm volatile ("leaveq\r\n"
                      "retq\r\n"
                      ::: "memory");
    }
}
