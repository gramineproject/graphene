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

#include "pal_defs.h"
#include "pal_freebsd_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_freebsd.h"
#include "pal_error.h"
#include "pal_security.h"
#include "api.h"
#include "list.h"

#include <atomic.h>
#include <sigset.h>
#include "signal.h"
#include <ucontext.h>
#include <errno.h>

typedef void (*PAL_UPCALL) (PAL_PTR, PAL_NUM, PAL_CONTEXT *);

int set_sighandler (int * sigs, int nsig, void * handler)
{
    struct sigaction action;
    action.sa_handler = (void (*)(int)) handler;
    action.sa_flags = SA_SIGINFO;

    __sigemptyset((_sigset_t *) &action.sa_mask);
    __sigaddset((_sigset_t *) &action.sa_mask, SIGCONT);

    for (int i = 0 ; i < nsig ; i++) {
        if (sigs[i] == SIGCHLD)
            action.sa_flags |= SA_NOCLDSTOP|SA_NOCLDWAIT;

#if defined(__i386__)
        int ret = INLINE_SYSCALL(sigaction, 3, sigs[i], &action, NULL)
#else
        int ret = INLINE_SYSCALL(sigaction, 4, sigs[i], &action, NULL,
                                 sizeof(sigset_t));
#endif
        if (IS_ERR(ret))
            return -PAL_ERROR_DENIED;

        action.sa_flags &= ~(SA_NOCLDSTOP|SA_NOCLDWAIT);
    }

    bool maskset = false;
    int ret = 0;
    _sigset_t mask;
    __sigemptyset(&mask);
    for (int i = 0 ; i < nsig ; i++)
        if (__sigismember(&bsd_state.sigset, sigs[i])) {
            __sigdelset(&bsd_state.sigset, sigs[i]);
            __sigaddset(&mask, sigs[i]);
            maskset = true;
        }

    if (maskset) {
#if defined(__i386__)
        ret = INLINE_SYSCALL(sigprocmask, 3, SIG_UNBLOCK, &mask, NULL)
#else
        ret = INLINE_SYSCALL(sigprocmask, 4, SIG_UNBLOCK, &mask, NULL,
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
    _sigset_t mask;
    __sigemptyset(&mask);
    for (int i = 0 ; i < nsig ; i++)
        if (!__sigismember(&bsd_state.sigset, sigs[i])) {
            __sigaddset(&bsd_state.sigset, sigs[i]);
            __sigaddset(&mask, sigs[i]);
            maskset = true;
        }

    if (maskset) {
#if defined(__i386__)
        ret = INLINE_SYSCALL(sigprocmask, 3, SIG_BLOCK, &mask, NULL)
#else
        ret = INLINE_SYSCALL(sigprocmask, 4, SIG_BLOCK, &mask, NULL,
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
    _sigset_t mask;
    __sigemptyset(&mask);
    for (int i = 0 ; i < nsig ; i++)
        if (__sigismember(&bsd_state.sigset, sigs[i])) {
            __sigdelset(&bsd_state.sigset, sigs[i]);
            __sigaddset(&mask, sigs[i]);
            maskset = true;
        }

    if (maskset) {
#if defined(__i386__)
        ret = INLINE_SYSCALL(sigprocmask, 3, SIG_UNBLOCK, &mask, NULL)
#else
        ret = INLINE_SYSCALL(sigprocmask, 4, SIG_UNBLOCK, &mask, NULL,
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
        int ret = INLINE_SYSCALL(sigaction, 4, sigs[i], SIG_DFL, NULL,
                                 sizeof(_sigset_t));
#endif
        if (IS_ERR(ret))
            return -PAL_ERROR_DENIED;
    }
    return 0;
}

struct exception_handler {
    struct mutex_handle lock;
    int flags;
    PAL_UPCALL upcall;

} __attribute__((aligned(sizeof(int))));

struct exception_event {

    int event_num;
    int flags;
    PAL_CONTEXT context;
    ucontext_t * uc;
    void * eframe;

};

#define DECLARE_HANDLER_HEAD(event)                         \
    static struct exception_handler handler_##event =       \
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

struct exception_handler * pal_handlers [PAL_EVENT_NUM_BOUND] = {
        NULL, /* reserved */
        &handler_DivZero,
        &handler_MemFault,
        &handler_Illegal,
        &handler_Quit,
        &handler_Suspend,
        &handler_Resume,
        &handler_Failure,
    };

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

void _DkGenericEventTrigger (int event_num, PAL_UPCALL upcall,
                             int flags, PAL_NUM arg, struct pal_frame * frame,
                             ucontext_t * uc, void * eframe)
{
    struct exception_event event;

    event.event_num = event_num;
    event.flags = flags;
    if (uc) {
        event.context.r8  = uc->uc_mcontext.mc_r8;
        event.context.r9  = uc->uc_mcontext.mc_r9;
        event.context.r10 = uc->uc_mcontext.mc_r10;
        event.context.r11 = uc->uc_mcontext.mc_r11;
        event.context.r12 = uc->uc_mcontext.mc_r12;
        event.context.r13 = uc->uc_mcontext.mc_r13;
        event.context.r14 = uc->uc_mcontext.mc_r14;
        event.context.r15 = uc->uc_mcontext.mc_r15;
        event.context.rdi = uc->uc_mcontext.mc_rdi;
        event.context.rsi = uc->uc_mcontext.mc_rsi;
        event.context.rbp = uc->uc_mcontext.mc_rbp;
        event.context.rbx = uc->uc_mcontext.mc_rbx;
        event.context.rdx = uc->uc_mcontext.mc_rdx;
        event.context.rax = uc->uc_mcontext.mc_rax;
        event.context.rcx = uc->uc_mcontext.mc_rcx;
        event.context.rsp = uc->uc_mcontext.mc_rsp;
        event.context.rip = uc->uc_mcontext.mc_rip;
        event.context.efl = uc->uc_mcontext.mc_flags;
        event.context.err = uc->uc_mcontext.mc_err;
        event.context.trapno = uc->uc_mcontext.mc_trapno;
        event.context.csgsfs  = 0;
        event.context.oldmask = 0;
        event.context.cr2     = 0;
    }

    if (frame) {
        event.context.r15 = frame->arch.r15;
        event.context.r14 = frame->arch.r14;
        event.context.r13 = frame->arch.r13;
        event.context.r12 = frame->arch.r12;
        event.context.rdi = frame->arch.rdi;
        event.context.rsi = frame->arch.rsi;
        event.context.rbx = frame->arch.rbx;
        /* find last frame */
        event.context.rsp = frame->arch.rbp + sizeof(unsigned long) * 2;
        event.context.rbp = ((unsigned long *) frame->arch.rbp)[0];
        event.context.rip = ((unsigned long *) frame->arch.rbp)[1];
    }

    event.uc = uc;
    event.eframe = eframe;

    (*upcall) (&event, arg, &event.context);
}

static bool _DkGenericSignalHandle (int event_num, siginfo_t * info,
                                    struct pal_frame * frame,
                                    ucontext_t * uc, void * eframe)
{
    struct exception_handler * handler = pal_handlers[event_num];

    _DkMutexLock(&handler->lock);
    PAL_UPCALL upcall = handler->upcall;
    int flags = handler->flags;
    _DkMutexUnlock(&handler->lock);

    if (upcall) {
        PAL_NUM arg = 0;


        if (event_num == PAL_EVENT_DIVZERO ||
            event_num == PAL_EVENT_MEMFAULT ||
            event_num == PAL_EVENT_ILLEGAL)
            arg = (PAL_NUM) (info ? info->si_addr : 0);

        _DkGenericEventTrigger(event_num, upcall, flags, arg, frame,
                               uc, eframe);
        return true;
    }

    return false;
}

#define ADDR_IN_PAL(addr) \
        ((void *) (addr) > TEXT_START && (void *) (addr) < TEXT_END)

static struct pal_frame * get_frame (ucontext_t * uc)
{
    unsigned long rip = uc->uc_mcontext.mc_rip;
    unsigned long rbp = uc->uc_mcontext.mc_rbp;
    unsigned long last_rbp = rbp - 1024;

    if (!ADDR_IN_PAL(rip))
        return NULL;

    while (ADDR_IN_PAL(((unsigned long *) rbp)[1])) {
        last_rbp = rbp;
        rbp = *(unsigned long *) rbp;
    }

    /* search frame record in the top frame of PAL */
    for (unsigned long ptr = rbp - sizeof(unsigned long) ;
         ptr > last_rbp ; ptr -= 8) {
        struct pal_frame * frame = (struct pal_frame *) ptr;
        if (frame->identifier == PAL_FRAME_IDENTIFIER)
            return frame;
    }

    return NULL;
}

static void return_frame (struct pal_frame * frame, int err)
{
    if (err)
        _DkRaiseFailure(err);

    __clear_frame(frame);
    arch_restore_frame(&frame->arch);
    asm volatile ("xor %%rax, %%rax\r\n"
                  "leaveq\r\n"
                  "retq\r\n" ::: "memory");
}

static void _DkGenericSighandler (int signum, siginfo_t * info,
                                  ucontext_t * uc)
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

    }
#endif

    struct pal_frame * frame = get_frame(uc);
    void * eframe;

    asm volatile ("movq %%rbp, %0" : "=r"(eframe));

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

    _DkGenericSignalHandle(event_num, info, frame, uc, eframe);
}

static void _DkTerminateSighandler (int signum, siginfo_t * info,
                                    ucontext_t * uc)
{
    struct pal_frame * frame = get_frame(uc);
    void * eframe;

    asm volatile ("movq %%rbp, %0" : "=r"(eframe));

    int event_num = get_event_num(signum);
    if (event_num == -1)
        return;

    if (!_DkGenericSignalHandle(event_num, NULL, frame, uc, eframe))
        _DkThreadExit();
}

static void _DkPipeSighandler (int signum, siginfo_t * info,
                               ucontext_t * uc)
{
    struct pal_frame * frame = get_frame(uc);
    if (frame)
        return_frame(frame, PAL_ERROR_CONNFAILED);
}

void _DkRaiseFailure (int error)
{
    _DkMutexLock(&handler_Failure.lock);
    PAL_UPCALL upcall = handler_Failure.upcall;
    int flags = handler_Failure.flags;
    _DkMutexUnlock(&handler_Failure.lock);

    if (upcall)
        _DkGenericEventTrigger(PAL_EVENT_FAILURE, upcall, flags, error,
                               NULL, NULL, NULL);
}

struct signal_ops {
    int signum[3];
    void (*handler) (int signum, siginfo_t * info, ucontext_t * uc);

};

struct signal_ops on_signals[PAL_EVENT_NUM_BOUND] = {
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
    struct exception_handler * handler = pal_handlers[event_num];

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
    struct exception_handler * handler = pal_handlers[event_num];
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
    struct exception_handler * handler = pal_handlers[event_num];

    _DkMutexLock(&handler->lock);
    handler->upcall = upcall;
    handler->flags = flags;
    _DkMutexUnlock(&handler->lock);

    return 0;
}

typedef void (*PAL_UPCALL) (PAL_PTR, PAL_NUM, PAL_CONTEXT *);

int (*_DkExceptionHandlers[PAL_EVENT_NUM_BOUND])
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
                                        ucontext_t * uc)
{
    /* not implemented */
}

void signal_setup (void)
{
    int ret, sig;
    __sigemptyset(&bsd_state.sigset);

    struct sigaction action;
    action.sa_handler = (void (*)(int)) SIG_IGN;
    action.sa_flags = 0;

#if defined(__i386__)
    ret = INLINE_SYSCALL(sigaction, 3, SIGCHLD, &action, NULL)
#else
    ret = INLINE_SYSCALL(sigaction, 4, SIGCHLD, &action, NULL,
                         sizeof(sigset_t));
#endif
    if (IS_ERR(ret)) {
        ret = -PAL_ERROR_DENIED;
        goto err;
    }

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

    return;

err:
    init_fail(-ret, "cannot setup signal handlers");
}

void _DkExceptionReturn (void * event)
{
    const struct exception_event * e = (const struct exception_event *) event;
    if (e->uc) {
        /* copy the context back to ucontext */
        e->uc->uc_mcontext.mc_r8 = e->context.r8;
        e->uc->uc_mcontext.mc_r9 = e->context.r9;
        e->uc->uc_mcontext.mc_r10 = e->context.r10;
        e->uc->uc_mcontext.mc_r11 = e->context.r11;
        e->uc->uc_mcontext.mc_r12 = e->context.r12;
        e->uc->uc_mcontext.mc_r13 = e->context.r13;
        e->uc->uc_mcontext.mc_r14 = e->context.r14;
        e->uc->uc_mcontext.mc_r15 = e->context.r15;
        e->uc->uc_mcontext.mc_rdi = e->context.rdi;
        e->uc->uc_mcontext.mc_rsi = e->context.rsi;
        e->uc->uc_mcontext.mc_rbp = e->context.rbp;
        e->uc->uc_mcontext.mc_rbx = e->context.rbx;
        e->uc->uc_mcontext.mc_rdx = e->context.rdx;
        e->uc->uc_mcontext.mc_rax = e->context.rax;
        e->uc->uc_mcontext.mc_rcx = e->context.rcx;
        e->uc->uc_mcontext.mc_rsp = e->context.rsp;
        e->uc->uc_mcontext.mc_rip = e->context.rip;
        e->uc->uc_mcontext.mc_flags = e->context.efl;
        e->uc->uc_mcontext.mc_err = e->context.err;
        e->uc->uc_mcontext.mc_trapno = e->context.trapno;

        /* return to the frame of exception handler */
        asm volatile ("movq %0, %%rbp\r\n"
                      "leaveq\r\n"
                      "retq\r\n" :: "r"(e->eframe) : "memory");
    }
}
