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
 * shim_signal.c
 *
 * This file contains codes to handle signals and exceptions passed from PAL.
 */

#include <shim_internal.h>
#include <shim_utils.h>
#include <shim_table.h>
#include <shim_thread.h>
#include <shim_handle.h>
#include <shim_vma.h>
#include <shim_checkpoint.h>
#include <shim_signal.h>
#include <shim_unistd.h>

#include <pal.h>

static struct shim_signal **
allocate_signal_log (struct shim_thread * thread, int sig)
{
    if (!thread->signal_logs)
        return NULL;

    struct shim_signal_log * log = &thread->signal_logs[sig - 1];
    int head, tail, old_tail;

    do {
        head = atomic_read(&log->head);
        old_tail = tail = atomic_read(&log->tail);

        if (head == tail + 1 || (!head && tail == (MAX_SIGNAL_LOG - 1)))
            return NULL;

        tail = (tail == MAX_SIGNAL_LOG - 1) ? 0 : tail + 1;
    } while (atomic_cmpxchg(&log->tail, old_tail, tail) == tail);

    atomic_inc(&thread->has_signal);

    return &log->logs[old_tail];
}

static struct shim_signal *
fetch_signal_log (shim_tcb_t * tcb, struct shim_thread * thread, int sig)
{
    struct shim_signal_log * log = &thread->signal_logs[sig - 1];
    struct shim_signal * signal = NULL;
    int head, tail, old_head;

    while (1) {
        old_head = head = atomic_read(&log->head);
        tail = atomic_read(&log->tail);

        if (head == tail)
            return NULL;

        if (!(signal = log->logs[head]))
            return NULL;

        log->logs[head] = NULL;
        head = (head == MAX_SIGNAL_LOG - 1) ? 0 : head + 1;

        if (atomic_cmpxchg(&log->head, old_head, head) == old_head)
            break;

        log->logs[old_head] = signal;
    }

    atomic_dec(&thread->has_signal);

    return signal;
}

static void
__handle_one_signal (shim_tcb_t * tcb, int sig, struct shim_signal * signal);

static void __store_info (siginfo_t * info, struct shim_signal * signal)
{
    if (info)
        memcpy(&signal->info, info, sizeof(siginfo_t));
}

void __store_context (shim_tcb_t * tcb, PAL_CONTEXT * pal_context,
                      struct shim_signal * signal)
{
    ucontext_t * context = &signal->context;

    if (tcb && tcb->context.syscall_nr) {
        struct shim_context * ct = &tcb->context;

        context->uc_mcontext.gregs[REG_RSP] = (unsigned long) ct->sp;
        context->uc_mcontext.gregs[REG_RIP] = (unsigned long) ct->ret_ip;

        if (ct->regs) {
            struct shim_regs * regs = ct->regs;
            context->uc_mcontext.gregs[REG_R15] = regs->r15;
            context->uc_mcontext.gregs[REG_R14] = regs->r14;
            context->uc_mcontext.gregs[REG_R13] = regs->r13;
            context->uc_mcontext.gregs[REG_R9]  = regs->r9;
            context->uc_mcontext.gregs[REG_R8]  = regs->r8;
            context->uc_mcontext.gregs[REG_RCX] = regs->rcx;
            context->uc_mcontext.gregs[REG_RDX] = regs->rdx;
            context->uc_mcontext.gregs[REG_RSI] = regs->rsi;
            context->uc_mcontext.gregs[REG_RDI] = regs->rdi;
            context->uc_mcontext.gregs[REG_R12] = regs->r12;
            context->uc_mcontext.gregs[REG_RBX] = regs->rbx;
            context->uc_mcontext.gregs[REG_RBP] = regs->rbp;
        }

        signal->context_stored = true;
        return;
    }

    if (pal_context) {
        memcpy(context->uc_mcontext.gregs, pal_context, sizeof(PAL_CONTEXT));
        signal->context_stored = true;
    }
}

void deliver_signal (siginfo_t * info, PAL_CONTEXT * context)
{
    shim_tcb_t * tcb = SHIM_GET_TLS();

    if (!tcb || !tcb->tp)
        return;

    struct shim_thread * cur_thread = (struct shim_thread *) tcb->tp;
    int sig = info->si_signo;

    __disable_preempt(tcb);

    struct shim_signal * signal = __alloca(sizeof(struct shim_signal));
    /* save in signal */
    memset(signal, 0, sizeof(struct shim_signal));
    __store_info(info, signal);
    __store_context(tcb, context, signal);

    if ((tcb->context.preempt & ~SIGNAL_DELAYED) > 1)
        goto delay;

    if (__sigismember(&cur_thread->signal_mask, sig))
        goto delay;

    __handle_signal(tcb, sig, &signal->context);
    __handle_one_signal(tcb, sig, signal);
    goto out;

delay:
    {
        if (!(signal = remalloc(signal,sizeof(struct shim_signal))))
            goto out;

        struct shim_signal ** signal_log = allocate_signal_log(cur_thread, sig);

        if (!signal_log) {
            sys_printf("signal queue is full (TID = %u, SIG = %d)\n",
                       tcb->tid, sig);
            free(signal);
            goto out;
        }

        *signal_log = signal;
    }

out:
    __enable_preempt(tcb);
}

#define ALLOC_SIGINFO(signo, member, value)                 \
    ({                                                      \
        siginfo_t * _info = __alloca(sizeof(siginfo_t));    \
        memset(_info, 0, sizeof(siginfo_t));                \
        _info->si_signo = (signo);                          \
        _info->member = (value);                            \
        _info;                                              \
    })

#ifdef __x86_64__
#define IP rip
#else
#define IP eip
#endif

#define is_internal(context)                                                \
    ((context) &&                                                           \
     (void *) (context)->IP >= (void *) &__code_address &&                  \
     (void *) (context)->IP < (void *) &__code_address_end)

#define internal_fault(errstr, addr, context)                               \
    do {                                                                    \
        IDTYPE tid = get_cur_tid();                                         \
        if (is_internal((context)))                                         \
            sys_printf(errstr " at %p (IP = +0x%lx, VMID = %u, TID = %u)\n",\
                       arg,                                                 \
                       (void *) context->IP - (void *) &__load_address,     \
                       cur_process.vmid, IS_INTERNAL_TID(tid) ? 0 : tid);   \
        else                                                                \
            sys_printf(errstr " at %p (IP = %p, VMID = %u, TID = %u)\n",    \
                       arg, context ? context->IP : 0,                      \
                       cur_process.vmid, IS_INTERNAL_TID(tid) ? 0 : tid);   \
    } while (0)

static void divzero_upcall (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    if (IS_INTERNAL_TID(get_cur_tid()) || is_internal(context)) {
        internal_fault("Internal arithmetic fault", arg, context);
        pause();
        goto ret_exception;
    }

    if (context)
        debug("arithmetic fault at %p\n", context->IP);

    deliver_signal(ALLOC_SIGINFO(SIGFPE, si_addr, (void *) arg), context);

ret_exception:
    DkExceptionReturn(event);
}

static void memfault_upcall (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    if (IS_INTERNAL_TID(get_cur_tid()) || is_internal(context)) {
internal:
        internal_fault("Internal memory fault", arg, context);
        pause();
        goto ret_exception;
    }

    struct shim_vma * vma = NULL;

    if (!(lookup_supervma((void *) arg, 0, &vma)) &&
        !(vma->flags & VMA_INTERNAL)) {
        int signo = SIGSEGV;

        if (context)
            debug("memory fault at %p (IP = %p)\n", arg, context->IP);

        if (vma)
            put_vma(vma);

        deliver_signal(ALLOC_SIGINFO(signo, si_addr, (void *) arg), context);
    } else {
        if (vma)
            put_vma(vma);

        goto internal;
    }

ret_exception:
    DkExceptionReturn(event);
}

static void illegal_upcall (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    if (IS_INTERNAL_TID(get_cur_tid()) || is_internal(context)) {
internal:
        internal_fault("Internal memory fault", arg, context);
        pause();
        goto ret_exception;
    }

    struct shim_vma * vma = NULL;

    if (!(lookup_supervma((void *) arg, 0, &vma)) &&
        !(vma->flags & VMA_INTERNAL)) {
        if (context)
            debug("illegal instruction at %p\n", context->IP);

        if (vma)
            put_vma(vma);

        deliver_signal(ALLOC_SIGINFO(SIGILL, si_addr, (void *) arg), context);
    } else {
        if (vma)
            put_vma(vma);

        goto internal;
    }

ret_exception:
    DkExceptionReturn(event);
}

static void quit_upcall (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    if (IS_INTERNAL_TID(get_cur_tid()))
        goto ret_exception;

    deliver_signal(ALLOC_SIGINFO(SIGTERM, si_pid, 0), NULL);

ret_exception:
    DkExceptionReturn(event);
}

bool ask_for_checkpoint = false;

static void suspend_upcall (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    if (IS_INTERNAL_TID(get_cur_tid()))
        goto ret_exception;

    deliver_signal(ALLOC_SIGINFO(SIGINT, si_pid, 0), NULL);

ret_exception:
    DkExceptionReturn(event);
}

static void resume_upcall (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    if (IS_INTERNAL_TID(get_cur_tid()))
        goto ret_exception;

    shim_tcb_t * tcb = SHIM_GET_TLS();

    if (!tcb || !tcb->tp)
        return;

    __disable_preempt(tcb);

    if ((tcb->context.preempt & ~SIGNAL_DELAYED) > 1) {
        tcb->context.preempt |= SIGNAL_DELAYED;
        __enable_preempt(tcb);
        goto ret_exception;
    }

    __handle_signal(tcb, 0, NULL);
    __enable_preempt(tcb);

ret_exception:
    DkExceptionReturn(event);
}

int init_signal (void)
{
    DkSetExceptionHandler(&divzero_upcall,     PAL_EVENT_DIVZERO,      0);
    DkSetExceptionHandler(&memfault_upcall,    PAL_EVENT_MEMFAULT,     0);
    DkSetExceptionHandler(&illegal_upcall,     PAL_EVENT_ILLEGAL,      0);
    DkSetExceptionHandler(&quit_upcall,        PAL_EVENT_QUIT,         0);
    DkSetExceptionHandler(&suspend_upcall,     PAL_EVENT_SUSPEND,      0);
    DkSetExceptionHandler(&resume_upcall,      PAL_EVENT_RESUME,       0);
    return 0;
}

__sigset_t * get_sig_mask (struct shim_thread * thread)
{
    if (!thread)
        thread = get_cur_thread();

    assert(thread);

    return &(thread->signal_mask);
}

__sigset_t * set_sig_mask (struct shim_thread * thread, __sigset_t * set)
{
    if (!thread)
        thread = get_cur_thread();

    assert(thread);

    if (set)
        memcpy(&thread->signal_mask, set, sizeof(__sigset_t));

    return &thread->signal_mask;
}

static void (*default_sighandler[NUM_SIGS]) (int, siginfo_t *, void *);

static void
__handle_one_signal (shim_tcb_t * tcb, int sig, struct shim_signal * signal)
{
    struct shim_thread * thread = (struct shim_thread *) tcb->tp;
    struct shim_signal_handle * sighdl = &thread->signal_handles[sig - 1];
    void (*handler) (int, siginfo_t *, void *) = NULL;

    if (signal->info.si_signo == SIGCP) {
        join_checkpoint(thread, &signal->context, si_cp_session(&signal->info));
        return;
    }

    debug("%s handled\n", signal_name(sig));

    lock(thread->lock);

    if (sighdl->action) {
        struct __kernel_sigaction * act = sighdl->action;
        /* This is a workaround. The truth is that many program will
           use sa_handler as sa_sigaction, because sa_sigaction is
           not supported in amd64 */
#ifdef __i386__
        handler = (void (*) (int, siginfo_t *, void *)) act->_u._sa_handler;
        if (act->sa_flags & SA_SIGINFO)
            sa_handler = act->_u._sa_sigaction;
#else
        handler = (void (*) (int, siginfo_t *, void *)) act->k_sa_handler;
#endif
        if (act->sa_flags & SA_RESETHAND) {
            sighdl->action = NULL;
            free(act);
        }
    }

    unlock(thread->lock);

    if ((void *) handler == (void *) 1) /* SIG_IGN */
        return;

    if (!handler && !(handler = default_sighandler[sig - 1]))
        return;

    /* if the context is never stored in the signal, it means the
       signal is handled during system calls, and before the thread
       is resumed. */
    if (!signal->context_stored)
        __store_context(tcb, NULL, signal);

    struct shim_context * context = NULL;

    if (tcb->context.syscall_nr) {
        context = __alloca(sizeof(struct shim_context));
        memcpy(context, &tcb->context, sizeof(struct shim_context));
        tcb->context.syscall_nr = 0;
        tcb->context.next = context;
    }

    debug("run signal handler %p (%d, %p, %p)\n", handler, sig, &signal->info,
          &signal->context);

    (*handler) (sig, &signal->info, &signal->context);

    if (context)
        memcpy(&tcb->context, context, sizeof(struct shim_context));
}

void __handle_signal (shim_tcb_t * tcb, int sig, ucontext_t * uc)
{
    struct shim_thread * thread = (struct shim_thread *) tcb->tp;
    int begin_sig = 1, end_sig = NUM_KNOWN_SIGS;

    if (sig)
        end_sig = (begin_sig = sig) + 1;

    sig = begin_sig;

    if (!thread->has_signal.counter)
        return;

    while (atomic_read(&thread->has_signal)) {
        struct shim_signal * signal = NULL;

        for ( ; sig < end_sig ; sig++)
            if (!__sigismember(&thread->signal_mask, sig) &&
                (signal = fetch_signal_log(tcb, thread, sig)))
                break;

        if (!signal)
            break;

        if (!signal->context_stored)
            __store_context(tcb, NULL, signal);

        __handle_one_signal(tcb, sig, signal);
        free(signal);
        DkThreadYieldExecution();
    }

    tcb->context.preempt &= ~SIGNAL_DELAYED;
}

void handle_signal (bool delayed_only)
{
    shim_tcb_t * tcb = SHIM_GET_TLS();

    if (!tcb || !tcb->tp)
        return;

    struct shim_thread * thread = (struct shim_thread *) tcb->tp;

    /* Fast path */
    if (!thread->has_signal.counter)
        return;

    __disable_preempt(tcb);

    if ((tcb->context.preempt & ~SIGNAL_DELAYED) > 1) {
        tcb->context.preempt |= SIGNAL_DELAYED;
        goto out;
    }

    if (delayed_only && !(tcb->context.preempt & SIGNAL_DELAYED))
        goto out;

    __handle_signal(tcb, 0, NULL);
out:
    __enable_preempt(tcb);
}

void append_signal (struct shim_thread * thread, int sig, siginfo_t * info,
                    bool wakeup)
{
    struct shim_signal * signal = malloc(sizeof(struct shim_signal));
    if (!signal)
        return;

    /* save in signal */
    if (info) {
        __store_info(info, signal);
        signal->context_stored = false;
    } else {
        memset(signal, 0, sizeof(struct shim_signal));
    }

    struct shim_signal ** signal_log = allocate_signal_log(thread, sig);

    if (signal_log) {
        *signal_log = signal;
        if (wakeup) {
            debug("resuming thread %u\n", thread->tid);
            DkThreadResume(thread->pal_handle);
        }
    } else {
        sys_printf("signal queue is full (TID = %u, SIG = %d)\n",
                   thread->tid, sig);
        free(signal);
    }
}

static void sighandler_kill (int sig, siginfo_t * info, void * ucontext)
{
    debug("killed by %s\n", signal_name(sig));

    if (!info->si_pid)
        switch(sig) {
            case SIGTERM:
            case SIGINT:
                shim_do_kill(-1, sig);
                break;
        }

    try_process_exit(0);
    DkThreadExit();
}

static void (*default_sighandler[NUM_SIGS]) (int, siginfo_t *, void *) =
    {
        /* SIGHUP */    &sighandler_kill,
        /* SIGINT */    &sighandler_kill,
        /* SIGQUIT */   &sighandler_kill,
        /* SIGILL */    &sighandler_kill,
        /* SIGTRAP */   NULL,
        /* SIGABRT */   &sighandler_kill,
        /* SIGBUS */    &sighandler_kill,
        /* SIGFPE */    &sighandler_kill,
        /* SIGKILL */   &sighandler_kill,
        /* SIGUSR1 */   NULL,
        /* SIGSEGV */   &sighandler_kill,
        /* SIGUSR2 */   NULL,
        /* SIGPIPE */   &sighandler_kill,
        /* SIGALRM */   NULL,
        /* SIGTERM */   &sighandler_kill,
        /* SIGSTKFLT */ NULL,
        /* SIGCHLD */   NULL,
        /* SIGCONT */   NULL,
        /* SIGSTOP */   NULL,
        /* SIGTSTP */   NULL,
        /* SIGTTIN */   NULL,
        /* SIGTTOU */   NULL,
    };
