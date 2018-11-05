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
#include "pal_linux_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_debug.h"
#include "pal_error.h"
#include "pal_security.h"
#include "api.h"

#include <atomic.h>
#include <sigset.h>
#include <linux/signal.h>
#include <ucontext.h>
#include <asm/errno.h>

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

    if (handler) {
        action.sa_handler = (void (*)(int)) handler;
        action.sa_flags = SA_SIGINFO;
#if !defined(__i386__)
        action.sa_flags |= SA_RESTORER;
        action.sa_restorer = restore_rt;
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
        int ret = INLINE_SYSCALL(rt_sigaction, 4, sigs[i], &action, NULL,
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
} PAL_EVENT;

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
                             PAL_NUM arg, ucontext_t * uc)
{
    PAL_EVENT event;
    event.event_num = event_num;

    if (uc)
        memcpy(&event.context, uc->uc_mcontext.gregs, sizeof(PAL_CONTEXT));

    event.uc = uc;

    (*upcall) ((PAL_PTR) &event, arg, &event.context);
}

static bool _DkGenericSignalHandle (int event_num, siginfo_t * info,
                                    ucontext_t * uc)
{
    PAL_EVENT_HANDLER upcall = _DkGetExceptionHandler(event_num);

    if (upcall) {
        PAL_NUM arg = 0;

        if (event_num == PAL_EVENT_DIVZERO ||
            event_num == PAL_EVENT_MEMFAULT ||
            event_num == PAL_EVENT_ILLEGAL)
            arg = (PAL_NUM) (info ? info->si_addr : 0);

        _DkGenericEventTrigger(event_num, upcall, arg, uc);
        return true;
    }

    return false;
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

    int event_num = get_event_num(signum);
    if (event_num == -1)
        return;

    uintptr_t rip = uc->uc_mcontext.gregs[REG_RIP];
    if (ADDR_IN_PAL(rip)) {
        // We expect none of the memory faults, illegal instructions, or arithmetic exceptions
        // will happen in PAL. If these exceptions happen in PAL, exit the thread with loud warning.
        int pid = INLINE_SYSCALL(getpid, 0);
        int tid = INLINE_SYSCALL(gettid, 0);
        char * name = "exception";
        switch(event_num) {
            case PAL_EVENT_DIVZERO:  name = "div-by-zero exception"; break;
            case PAL_EVENT_MEMFAULT: name = "memory fault"; break;
            case PAL_EVENT_ILLEGAL:  name = "illegal instruction"; break;
        }

        printf("*** An unexpected %s occured inside PAL. Exiting the thread. "
               "(PID = %d, TID = %d, RIP = +%p) ***\n",
               name, pid, tid, rip - (uintptr_t) TEXT_START);
        _DkThreadExit();
        return;
    }

    _DkGenericSignalHandle(event_num, info, uc);
}

static void _DkTerminateSighandler (int signum, siginfo_t * info,
                                    struct ucontext * uc)
{
    int event_num = get_event_num(signum);
    if (event_num == -1)
        return;

    uintptr_t rip = uc->uc_mcontext.gregs[REG_RIP];

    // If the signal arrives in the middle of a PAL call, add the event
    // to pending in the current TCB.
    if (ADDR_IN_PAL(rip)) {
        PAL_TCB * tcb = get_tcb();
        assert(tcb);
        tcb->pending_event = event_num;
        return;
    }

    if (!_DkGenericSignalHandle(event_num, NULL, uc))
        _DkThreadExit();
}

static void _DkPipeSighandler (int signum, siginfo_t * info,
                               struct ucontext * uc)
{
    uintptr_t rip = uc->uc_mcontext.gregs[REG_RIP];
    assert(ADDR_IN_PAL(rip)); // This signal can only happens inside PAL
    return;
}

/*
 * __check_pending_event(): checks the existence of a pending event in the TCB
 * and handles the event consequently.
 */
void __check_pending_event (void)
{
    PAL_TCB * tcb = get_tcb();
    assert(tcb);
    if (tcb->pending_event) {
        int event = tcb->pending_event;
        tcb->pending_event = 0;
        _DkGenericSignalHandle(event, NULL, NULL);
    }
}

void _DkRaiseFailure (int error)
{
    PAL_EVENT_HANDLER upcall = _DkGetExceptionHandler(PAL_EVENT_FAILURE);

    if (!upcall)
        return;

    PAL_EVENT event;
    event.event_num = PAL_EVENT_FAILURE;
    event.uc = NULL;

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
                                    .handler = _DkTerminateSighandler },
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
    if (e->uc) {
        /* copy the context back to ucontext */
        memcpy(e->uc->uc_mcontext.gregs, &e->context, sizeof(PAL_CONTEXT));
    }
}
