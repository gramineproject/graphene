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

#include <atomic.h>
#include <sigset.h>
#include <ucontext.h>
#include <errno.h>

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

#endif

int set_sighandler (int * sigs, int nsig, void * handler)
{
    struct sigaction action;

    if (handler) {
        action.sa_handler = (void (*)(int)) handler;
        action.sa_flags = SA_SIGINFO;
#if !defined(__i386__)
        //action.sa_flags |= SA_RESTORER;
        //action.sa_restorer = restore_rt;
#endif
    } else {
        action.sa_handler = SIG_IGN;
    }

#ifdef DEBUG
    if (!linux_state.in_gdb)
#endif
        action.sa_flags |= SA_NOCLDWAIT;

    __sigemptyset((__sigset_t *) &action.sa_mask);
    __sigaddset((__sigset_t *) &action.sa_mask, SIGCONT);

    for (int i = 0 ; i < nsig ; i++) {
#if defined(__i386__)
        int ret = INLINE_SYSCALL(sigaction, 3, sigs[i], &action, NULL)
#else
        int ret = INLINE_SYSCALL(sigaction, 4, sigs[i], &action, NULL,
                                 sizeof(sigset_t));
#endif
        if (IS_ERR(ret))
            return -PAL_ERROR_DENIED;
    }

    return 0;
}

typedef struct {
    PAL_IDX         event_num;
    PAL_CONTEXT     context;
    ucontext_t *    uc;
    PAL_PTR         eframe;
} PAL_EVENT;

#define SIGNAL_MASK_TIME 1000

static int get_event_num (int signum)
{
    switch(signum) {
        case SIGFPE:                return PAL_EVENT_DIVZERO;
        case SIGSEGV: case SIGBUS:  return PAL_EVENT_MEMFAULT;
        case SIGILL:  case SIGSYS:  return PAL_EVENT_ILLEGAL;
        case SIGTERM:               return PAL_EVENT_QUIT;
        case SIGINT:                return PAL_EVENT_SUSPEND;
        case SIGCONT:               return PAL_EVENT_RESUME;
        default: return -1;
    }
}

void _DkGenericEventTrigger (PAL_IDX event_num, PAL_EVENT_HANDLER upcall,
                             PAL_NUM arg, struct pal_frame * frame,
                             ucontext_t * uc, void * eframe)
{
    PAL_EVENT event;
    event.event_num = event_num;

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
        /* making rax = 0 to tell the caller that this PAL call failed */
        event.context.rax = 0;
    }

    event.uc = uc;
    event.eframe = eframe;

    (*upcall) ((PAL_PTR) &event, arg, &event.context);
}

static bool _DkGenericSignalHandle (int event_num, siginfo_t * info,
                                    struct pal_frame * frame,
                                    ucontext_t * uc, void * eframe)
{
    PAL_EVENT_HANDLER upcall = _DkGetExceptionHandler(event_num);

    if (upcall) {
        PAL_NUM arg = 0;

        if (event_num == PAL_EVENT_DIVZERO ||
            event_num == PAL_EVENT_MEMFAULT ||
            event_num == PAL_EVENT_ILLEGAL)
            arg = (PAL_NUM) (info ? info->si_addr : 0);

        _DkGenericEventTrigger(event_num, upcall, arg, frame, uc, eframe);
        return true;
    }

    return false;
}

#define ADDR_IN_PAL(addr) \
        ((void *) (addr) > TEXT_START && (void *) (addr) < TEXT_END)

/* This function walks the stack to find the PAL_FRAME
 * that was saved upon entry to the PAL, if an exception/interrupt
 * comes in during a PAL call.  This is needed to support the behavior that an
 * exception in the PAL has Unix-style, EAGAIN semantics.
 * 
 * The PAL_FRAME is supposed to be in the first PAL frame, and we look for 
 * it by matching a special magic number, that should only appear on the stack
 * once.
 * 
 * If an exception comes in while we are not in the PAL, this PAL_FRAME won't
 * exist, and it is ok to return NULL.
 */
static struct pal_frame * get_frame (ucontext_t * uc)
{
    unsigned long rip = uc->uc_mcontext.mc_rip;
    unsigned long rbp = uc->uc_mcontext.mc_rbp;
    unsigned long last_rbp = rbp - 64;

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

    asm volatile ("xor %rax, %rax\r\n"
                  "leaveq\r\n"
                  "retq\r\n");
}

#if BLOCK_SIGFAULT == 1
static char exception_msg[24] = "--- SIGSEGV --- [     ]\n";
static volatile bool cont_exec = false;
#endif

static void _DkGenericSighandler (int signum, siginfo_t * info,
                                  struct ucontext * uc)
{
#if BLOCK_SIGFUALT == 1
    /* reseurrect this code if signal handler if giving segmentation fault */
    if (signum == SIGSEGV) {
        int pid = INLINE_SYSCALL(getpid, 0);
        exception_msg[17] = '0' + pid / 10000;
        exception_msg[18] = '0' + (pid / 1000) % 10;
        exception_msg[19] = '0' + (pid / 100) % 10;
        exception_msg[20] = '0' + (pid / 10) % 10;
        exception_msg[21] = '0' + pid % 10;
        INLINE_SYSCALL(write, 3, 1, exception_msg, 24);
        while(!cont_exec);
    }
#endif

    struct pal_frame * frame = get_frame(uc);
    void * eframe;

    if (signum == SIGCONT && frame && frame->func == DkObjectsWaitAny)
        return;

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
                                    struct ucontext * uc)
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
                               struct ucontext * uc)
{
    return;
}

void _DkRaiseFailure (int error)
{
    PAL_EVENT_HANDLER upcall = _DkGetExceptionHandler(PAL_EVENT_FAILURE);

    if (!upcall)
        return;

    PAL_EVENT event;
    event.event_num = PAL_EVENT_FAILURE;
    event.uc = NULL;
    event.eframe = NULL;

    (*upcall) ((PAL_PTR) &event, error, NULL);
}

struct signal_ops {
    int signum[3];
    void (*handler) (int signum, siginfo_t * info, ucontext_t * uc);
};

struct signal_ops on_signals[] = {
        [PAL_EVENT_DIVZERO]     = { .signum = { SIGFPE, 0 },
                                    .handler = _DkGenericSighandler },
        [PAL_EVENT_MEMFAULT]    = { .signum = { SIGSEGV, SIGBUS, 0 },
                                    .handler = _DkGenericSighandler },
        [PAL_EVENT_ILLEGAL]     = { .signum = { SIGILL,  SIGSYS, 0 },
                                    .handler = _DkGenericSighandler },
        [PAL_EVENT_QUIT]        = { .signum = { SIGTERM, 0, 0 },
                                    .handler = _DkTerminateSighandler },
        [PAL_EVENT_SUSPEND]     = { .signum = { SIGINT, 0 },
                                    .handler = _DkTerminateSighandler },
        [PAL_EVENT_RESUME]      = { .signum = { SIGCONT, 0 },
                                    .handler = _DkGenericSighandler },
    };

static int _DkPersistentSighandlerSetup (int event_num)
{
    int nsigs, * sigs = on_signals[event_num].signum;
    for (nsigs = 0 ; sigs[nsigs] ; nsigs++);

    int ret = set_sighandler(sigs, nsigs, on_signals[event_num].handler);
    if (ret < 0)
        return ret;

    return 0;
}

void signal_setup (void)
{
    int ret, sig = SIGCHLD;

#ifdef DEBUG
    if (!linux_state.in_gdb)
#endif
        set_sighandler(&sig, 1, NULL);

    sig = SIGPIPE;
    if ((ret = set_sighandler(&sig, 1, &_DkPipeSighandler)) < 0)
        goto err;

    int events[] = {
        PAL_EVENT_DIVZERO,
        PAL_EVENT_MEMFAULT,
        PAL_EVENT_ILLEGAL,
        PAL_EVENT_QUIT,
        PAL_EVENT_SUSPEND,
        PAL_EVENT_RESUME,
    };

    for (int e = 0 ; e < sizeof(events) / sizeof(events[0]) ; e++)
        if ((ret = _DkPersistentSighandlerSetup(events[e])) < 0)
            goto err;

    return;
err:
    init_fail(-ret, "cannot setup signal handlers");
}

void _DkExceptionReturn (void * event)
{
    PAL_EVENT * e = event;

    if (e->eframe) {
        struct pal_frame * frame = (struct pal_frame *) e->eframe;
        int err = 0;

        switch (e->event_num) {
            case PAL_EVENT_MEMFAULT:
                err = PAL_ERROR_BADADDR;
                break;
            case PAL_EVENT_QUIT:
            case PAL_EVENT_SUSPEND:
            case PAL_EVENT_RESUME:
                err = PAL_ERROR_INTERRUPTED;
                break;
        }

        if (err)
            _DkRaiseFailure(err);

        __clear_frame(frame);
    }

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
