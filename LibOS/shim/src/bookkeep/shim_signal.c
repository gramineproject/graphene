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

    debug("signal_logs[%d]: head=%d, tail=%d (counter = %d)\n", sig - 1,
          head, tail, thread->has_signal.counter + 1);

    atomic_inc(&thread->has_signal);

#if 0
    // TODO: XXX ??? why thread->tcb seems stale?
    if (thread->tcb)
        set_bit(SHIM_FLAG_SIGPENDING, &(((shim_tcb_t*)thread->tcb)->flags));
#endif

    debug("signal set_bit thread: %p tcb: %p &tcb->flags: %p tcb->flags 0x%x "
          "tcb->tid %d counter = %d\n",
          thread, thread->tcb, &(((shim_tcb_t*)thread->tcb)->flags),
          ((shim_tcb_t*)thread->tcb)->flags, ((shim_tcb_t*)thread->tcb)->tid,
        thread->has_signal.counter);

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

    debug("signal_logs[%d]: head=%d, tail=%d\n", sig -1, head, tail);

    atomic_dec(&thread->has_signal);

    return signal;
}

static void
__handle_one_signal (shim_tcb_t * tcb, int sig, struct shim_signal * signal,
                     PAL_EVENT * event);

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
            context->uc_mcontext.gregs[REG_R12] = regs->r12;
            context->uc_mcontext.gregs[REG_R11] = regs->r11;
            context->uc_mcontext.gregs[REG_R10] = regs->r10;
            context->uc_mcontext.gregs[REG_R9]  = regs->r9;
            context->uc_mcontext.gregs[REG_R8]  = regs->r8;
            context->uc_mcontext.gregs[REG_RCX] = regs->rcx;
            context->uc_mcontext.gregs[REG_RDX] = regs->rdx;
            context->uc_mcontext.gregs[REG_RSI] = regs->rsi;
            context->uc_mcontext.gregs[REG_RDI] = regs->rdi;
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

void deliver_signal (PAL_PTR event, siginfo_t * info, PAL_CONTEXT * context)
{
    shim_tcb_t * tcb = SHIM_GET_TLS();
    assert(tcb);

    // Signals should not be delivered before the user process starts
    // or after the user process dies.
    if (!tcb->tp || !cur_thread_is_alive())
        return;

    struct shim_thread * cur_thread = (struct shim_thread *) tcb->tp;
    int sig = info->si_signo;

    __disable_preempt(tcb);

    struct shim_signal * signal = __alloca(sizeof(struct shim_signal));
    /* save in signal */
    memset(signal, 0, sizeof(struct shim_signal));
    __store_info(info, signal);
    __store_context(tcb, context, signal);
    signal->pal_context = context;

    if ((tcb->context.preempt & ~SIGNAL_DELAYED) > 1 ||
        __sigismember(&cur_thread->signal_mask, sig) ||
        event == NULL /* send to self */) {
        struct shim_signal ** signal_log = NULL;
        if ((signal = malloc_copy(signal,sizeof(struct shim_signal))) &&
            (signal_log = allocate_signal_log(cur_thread, sig))) {
            *signal_log = signal;
        }
        if (signal && !signal_log) {
            sys_printf("signal queue is full (TID = %u, SIG = %d)\n",
                       tcb->tid, sig);
            free(signal);
        }
    } else {
        if (!__handle_signal(tcb, sig, &signal->context, event))
            __handle_one_signal(tcb, sig, signal, event);
    }

    __enable_preempt(tcb);
}

#define ALLOC_SIGINFO(signo, code, member, value)           \
    ({                                                      \
        siginfo_t * _info = __alloca(sizeof(siginfo_t));    \
        memset(_info, 0, sizeof(siginfo_t));                \
        _info->si_signo = (signo);                          \
        _info->si_code = (code);                            \
        _info->member = (value);                            \
        _info;                                              \
    })

#ifdef __x86_64__
#define IP rip
#else
#define IP eip
#endif

static inline bool is_internal(PAL_CONTEXT * context)
{
    return context &&
        (void *) context->IP >= (void *) &__code_address &&
        (void *) context->IP < (void *) &__code_address_end;
}

static inline bool is_signal_allowed(const PAL_CONTEXT * context)
{
    if (context == NULL)
        return false;

    const void * ip = (const void *)context->IP;
    return (((void *) &__syscallas_signal_allowed_0_begin <= ip &&
             ip < (void *) &__syscallas_signal_allowed_0_end) ||
            ((void *) &__syscallas_signal_allowed_1_begin <= ip &&
             ip < (void *) &__syscallas_signal_allowed_1_end) ||
            ((void *) &__syscallas_signal_allowed_2_begin <= ip &&
             ip < (void *) &__syscallas_signal_allowed_2_end));
}

static inline bool is_sigreturn_jmp_emulation(const PAL_CONTEXT * context)
{
    return context != NULL &&
        (void *)context->IP == (void *)&__syscallas_need_emulate_jmp;
}

static inline void internal_fault(const char* errstr,
                                  PAL_NUM addr, PAL_CONTEXT * context)
{
    IDTYPE tid = get_cur_tid();
    if (is_internal(context))
        sys_printf("%s at %p (IP = +0x%lx, VMID = %u, TID = %u)\n", errstr,
                   addr, (void *) context->IP - (void *) &__load_address,
                   cur_process.vmid, IS_INTERNAL_TID(tid) ? 0 : tid);
    else
        sys_printf("%s at %p (IP = %p, VMID = %u, TID = %u)\n", errstr,
                   addr, context ? context->IP : 0,
                   cur_process.vmid, IS_INTERNAL_TID(tid) ? 0 : tid);

    pause();
}

static void divzero_upcall (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    if (IS_INTERNAL_TID(get_cur_tid()) || is_internal(context)) {
        internal_fault("Internal arithmetic fault", arg, context);
    } else {
        if (context)
            debug("arithmetic fault at %p\n", context->IP);

        deliver_signal(event, ALLOC_SIGINFO(SIGFPE, FPE_INTDIV,
                                            si_addr, (void *) arg), context);
    }
    DkExceptionReturn(event);
}

static void memfault_upcall (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    shim_tcb_t * tcb = SHIM_GET_TLS();
    assert(tcb);

    if (tcb->test_range.cont_addr && arg
        && (void *) arg >= tcb->test_range.start
        && (void *) arg <= tcb->test_range.end) {
        assert(context);
        context->rip = (PAL_NUM) tcb->test_range.cont_addr;
        goto ret_exception;
    }

    if (IS_INTERNAL_TID(get_cur_tid()) || is_internal(context)) {
        internal_fault("Internal memory fault", arg, context);
        goto ret_exception;
    }

    if (context)
        debug("memory fault at %p (IP = %p)\n", arg, context->IP);

    struct shim_vma_val vma;
    int signo = SIGSEGV;
    int code;
    if (!arg) {
        code = SEGV_MAPERR;
    } else if (!lookup_vma((void *) arg, &vma)) {
        if (vma.flags & VMA_INTERNAL) {
            internal_fault("Internal memory fault with VMA", arg, context);
            goto ret_exception;
        }
        if (vma.file && vma.file->type == TYPE_FILE) {
            /* DEP 3/3/17: If the mapping exceeds end of a file (but is in the VMA)
             * then return a SIGBUS. */
            uint64_t eof_in_vma = (uint64_t) vma.addr + vma.offset + vma.file->info.file.size;
            if (arg > eof_in_vma) {
                signo = SIGBUS;
                code = BUS_ADRERR;
            } else if ((context->err & 4) && !(vma.flags & PROT_WRITE)) {
                /* DEP 3/3/17: If the page fault gives a write error, and
                 * the VMA is read-only, return SIGSEGV+SEGV_ACCERR */
                signo = SIGSEGV;
                code = SEGV_ACCERR;
            } else {
                /* XXX: need more sophisticated judgement */
                signo = SIGBUS;
                code = BUS_ADRERR;
            }
        } else {
            code = SEGV_ACCERR;
        }
    } else {
        code = SEGV_MAPERR;
    }

    deliver_signal(event, ALLOC_SIGINFO(signo, code, si_addr, (void *) arg),
                   context);

ret_exception:
    DkExceptionReturn(event);
    return;
}

/*
 * 'test_user_memory' and 'test_user_string' are helper functions for testing
 * if a user-given buffer or data structure is readable / writable (according
 * to the system call semantics). If the memory test fails, the system call
 * should return -EFAULT or -EINVAL accordingly. These helper functions cannot
 * guarantee further corruption of the buffer, or if the buffer is unmapped
 * with a concurrent system call. The purpose of these functions is simply for
 * the compatibility with programs that rely on the error numbers, such as the
 * LTP test suite.
 */
bool test_user_memory (void * addr, size_t size, bool write)
{
    if (!size)
        return false;

    shim_tcb_t * tcb = SHIM_GET_TLS();
    assert(tcb && tcb->tp);
    __disable_preempt(tcb);

    if (addr + size - 1 < addr)
        size = (void *) 0x0 - addr;

    bool has_fault = true;

    /* Add the memory region to the watch list. This is not racy because
     * each thread has its own record. */
    assert(!tcb->test_range.cont_addr);
    tcb->test_range.cont_addr = &&ret_fault;
    tcb->test_range.start = addr;
    tcb->test_range.end = addr + size - 1;

    /* Try to read or write into one byte inside each page */
    void * tmp = addr;
    while (tmp <= addr + size - 1) {
        if (write) {
            *(volatile char *) tmp = *(volatile char *) tmp;
        } else {
            *(volatile char *) tmp;
        }
        tmp = ALIGN_UP(tmp + 1);
    }

    has_fault = false; /* All accesses have passed. Nothing wrong. */

ret_fault:
    /* If any read or write into the target region causes an exception,
     * the control flow will immediately jump to here. */
    tcb->test_range.cont_addr = NULL;
    tcb->test_range.start = tcb->test_range.end = NULL;
    __enable_preempt(tcb);
    return has_fault;
}

/*
 * This function tests a user string with unknown length. It only tests
 * whether the memory is readable.
 */
bool test_user_string (const char * addr)
{
    shim_tcb_t * tcb = SHIM_GET_TLS();
    assert(tcb && tcb->tp);
    __disable_preempt(tcb);

    bool has_fault = true;

    assert(!tcb->test_range.cont_addr);
    tcb->test_range.cont_addr = &&ret_fault;

    /* Test one page at a time. */
    const char * next = ALIGN_UP(addr + 1);
    do {
        /* Add the memory region to the watch list. This is not racy because
         * each thread has its own record. */
        tcb->test_range.start = (void *) addr;
        tcb->test_range.end = (void *) (next - 1);
        *(volatile char *) addr; /* try to read one byte from the page */

        /* If the string ends in this page, exit the loop. */
        if (strnlen(addr, next - addr) < next - addr)
            break;

        addr = next;
        next = ALIGN_UP(addr + 1);
    } while (addr < next);

    has_fault = false; /* All accesses have passed. Nothing wrong. */

ret_fault:
    /* If any read or write into the target region causes an exception,
     * the control flow will immediately jump to here. */
    tcb->test_range.cont_addr = NULL;
    tcb->test_range.start = tcb->test_range.end = NULL;
    __enable_preempt(tcb);
    return has_fault;
}

static void illegal_upcall (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    struct shim_vma_val vma;

    if (!IS_INTERNAL_TID(get_cur_tid()) &&
        !is_internal(context) &&
        !(lookup_vma((void *) arg, &vma)) &&
        !(vma.flags & VMA_INTERNAL)) {
        if (context)
            debug("illegal instruction at %p\n", context->IP);

        deliver_signal(event, ALLOC_SIGINFO(SIGILL, ILL_ILLOPC,
                                            si_addr, (void *) arg), context);
    } else {
        internal_fault("Internal illegal fault", arg, context);
    }
    DkExceptionReturn(event);
}

static void quit_upcall (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    if (!IS_INTERNAL_TID(get_cur_tid())) {
        deliver_signal(event, ALLOC_SIGINFO(SIGTERM, SI_USER, si_pid, 0), NULL);
    }
    DkExceptionReturn(event);
}

static void suspend_upcall (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    if (!IS_INTERNAL_TID(get_cur_tid())) {
        deliver_signal(event, ALLOC_SIGINFO(SIGINT, SI_USER, si_pid, 0), NULL);
    }
    DkExceptionReturn(event);
}

static void resume_upcall (PAL_PTR eventp, PAL_NUM arg, PAL_CONTEXT * context)
{
    shim_tcb_t * tcb = SHIM_GET_TLS();

    if (!IS_INTERNAL_TID(get_cur_tid())) {
        assert(tcb);
        __disable_preempt(tcb);

        if ((tcb->context.preempt & ~SIGNAL_DELAYED) > 1) {
            tcb->context.preempt |= SIGNAL_DELAYED;
        } else {
            PAL_EVENT * event = (PAL_EVENT *) eventp;
            debug("resume_upcall rsp: %p rip %p tid: %d\n",
                  context->rsp, context->rip, get_cur_tid());

            __handle_signal(tcb, 0, event->uc, event);
        }

        __enable_preempt(tcb);
    }

    DkExceptionReturn(eventp);
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

__sigset_t * set_sig_mask (struct shim_thread * thread,
                           const __sigset_t * set)
{
    if (!thread)
        thread = get_cur_thread();

    assert(thread);

    if (set)
        memcpy(&thread->signal_mask, set, sizeof(__sigset_t));

    return &thread->signal_mask;
}

static void (*default_sighandler[NUM_SIGS]) (int, siginfo_t *, void *);

static unsigned int fpstate_size_get(const struct _libc_fpstate * fpstate)
{
    if (fpstate == NULL)
        return 0;

    const struct _fpx_sw_bytes * sw = &fpstate->sw_reserved;
    if (sw->magic1 == FP_XSTATE_MAGIC1 &&
        sw->xstate_size < sw->extended_size &&
        *((typeof(FP_XSTATE_MAGIC2)*)((void*)fpstate + sw->xstate_size)) ==
        FP_XSTATE_MAGIC2)
        return sw->extended_size;

    return sizeof(struct swregs_state);
}

static void __setup_sig_frame(
    shim_tcb_t * tcb, int sig, struct shim_signal * signal,
    PAL_PTR eventp,
    void (*handler) (int, siginfo_t *, void *), void (*restorer) (void))
{
    PAL_EVENT * event = (PAL_EVENT *) eventp;
    //struct shim_thread * thread = (struct shim_thread *) tcb->tp;

    ucontext_t * uc = event->uc;
    struct _libc_fpstate * fpstate = uc->uc_mcontext.fpregs;
    unsigned int fpstate_size = fpstate_size_get(fpstate);

    long sp = uc->uc_mcontext.gregs[REG_RSP];
    sp -= 128;  /* redzone */
    fpregset_t user_fp = (fpregset_t)ALIGN_DOWN_PTR(sp - fpstate_size, 64UL);
    struct sigframe * user_sigframe = (struct sigframe *)ALIGN_DOWN_PTR(user_fp - sizeof(struct sigframe), 16UL) - 8;
    user_sigframe->restorer = restorer;
    memcpy(&user_sigframe->uc, uc, sizeof(*uc));
    /* For now sigaltstack isn't supported */
    stack_t * stack = &user_sigframe->uc.uc_stack;
    stack->ss_sp = 0;
    stack->ss_flags = SS_DISABLE;
    stack->ss_size = 0;
    memcpy(&user_sigframe->info, &signal->info, sizeof(signal->info));
    if (fpstate_size > 0) {
        memcpy(user_fp, fpstate, fpstate_size);
        user_sigframe->uc.uc_mcontext.fpregs = user_fp;
    } else {
        user_sigframe->uc.uc_mcontext.fpregs = NULL;
    }
    memcpy(&user_sigframe->uc.uc_sigmask, &uc->uc_sigmask,
           sizeof(user_sigframe->uc.uc_sigmask));

    PAL_CONTEXT * pal_context = signal->pal_context;
    if (pal_context) {
        pal_context->rsp = (long)user_sigframe;
        pal_context->rip = (long)handler;
        pal_context->rdi = signal->info.si_signo;
        pal_context->rsi = (long)&user_sigframe->info;
        pal_context->rdx = (long)&user_sigframe->uc;
        pal_context->rax = 0;
    }

    gregset_t * gregs = &uc->uc_mcontext.gregs;
    (*gregs)[REG_RSP] = (long)user_sigframe;
    (*gregs)[REG_RIP] = (long)handler;
    (*gregs)[REG_RDI] = (long)signal->info.si_signo;
    (*gregs)[REG_RSI] = (long)&user_sigframe->info;
    (*gregs)[REG_RDX] = (long)&user_sigframe->uc;
    (*gregs)[REG_RAX] = 0;

    // _DkExceptionReturn overwrite uc.uc_mcontext.gregs
    // PAL_CONTEXT == greg_t
    memcpy(&event->context, gregs, sizeof(PAL_CONTEXT));

    // keep fpu state to user signal handler
    uc->uc_mcontext.fpregs = NULL;
    uc->uc_flags &= ~UC_FP_XSTATE;

    debug("deliver signal handler to user stack %p (%d, %p, %p)\n",
          handler, sig, &signal->info, &signal->context);
}

static void get_signal_handler(struct shim_thread * thread, int sig,
                               void (**handler) (int, siginfo_t *, void *),
                               void (**restorer) (void))
{
    struct shim_signal_handle * sighdl = &thread->signal_handles[sig - 1];
    *handler = NULL;
    *restorer = NULL;

    lock(thread->lock);

    if (sighdl->action) {
        struct __kernel_sigaction * act = sighdl->action;
        /* This is a workaround. The truth is that many program will
           use sa_handler as sa_sigaction, because sa_sigaction is
           not supported in amd64 */
#ifdef __i386__
        *handler = (void (*) (int, siginfo_t *, void *)) act->_u._sa_handler;
        if (act->sa_flags & SA_SIGINFO)
            sa_handler = act->_u._sa_sigaction;
#else
        *handler = (void (*) (int, siginfo_t *, void *)) act->k_sa_handler;
#endif
        *restorer = act->sa_restorer;
        if (act->sa_flags & SA_RESETHAND) {
            sighdl->action = NULL;
            free(act);
        }
    }

    unlock(thread->lock);
}


static void
__handle_one_signal (shim_tcb_t * tcb, int sig, struct shim_signal * signal,
                     PAL_EVENT * event)
{
    struct shim_thread * thread = (struct shim_thread *) tcb->tp;
    void (*handler) (int, siginfo_t *, void *) = NULL;
    void (*restorer) (void) = NULL;

    if (signal->info.si_signo == SIGCP) {
        join_checkpoint(thread, &signal->context, si_cp_session(&signal->info));
        return;
    }

    debug("%s handled\n", signal_name(sig));

    get_signal_handler(thread, sig, &handler, &restorer);
    if ((void *) handler == (void *) 1) /* SIG_IGN */
        return;

    if (!handler && !(handler = default_sighandler[sig - 1]))
        return;

    /* if the context is never stored in the signal, it means the
       signal is handled during system calls, and before the thread
       is resumed. */
    if (!signal->context_stored)
        __store_context(tcb, NULL, signal);

    if (event != NULL &&
        (!is_internal(&event->context) || is_signal_allowed(&event->context)) &&
        !DkInPal(&event->context)) {
        if (is_sigreturn_jmp_emulation(&event->context)) {
            /* see syscallas.S */
            PAL_CONTEXT * context = &event->context;
            context->rip = *(long*)((void*)context->rsp - 128 - 8);

            gregset_t *gregset = &event->uc->uc_mcontext.gregs;
            (*gregset)[REG_RIP] = *(long*)((*gregset)[REG_RSP] - 128 - 8);
        }
        __setup_sig_frame(tcb, sig, signal, event, handler, restorer);
    } else {
        /*
         * host signal handler is called during PAL or LibOS.
         * It means thread is in systeam call emulation. actual signal
         * delivery is done by deliver_signal_on_sysret()
         */
        debug("appending signal for trigger syscall return  "
              "%p (%d, %p, %p)\n", handler, sig, &signal->info,
              &signal->context);
        debug("waking up for signal "
              "thread: %p tcb: %p, tcb->flags: %p 0x%x tid: %d\n",
              thread, tcb, &tcb->flags, tcb->flags, tcb->tid);
        set_bit(SHIM_FLAG_SIGPENDING, &(((shim_tcb_t*)thread->tcb)->flags));
    }
}

int __handle_signal (shim_tcb_t * tcb, int sig, ucontext_t * uc, PAL_EVENT * event)
{
    if (uc == NULL || event == NULL)
        return 0;

    if (event != NULL &&
        (is_internal(&event->context) &&
         !is_signal_allowed(&event->context) &&
         DkInPal(&event->context))) {
        debug("__handle_signal: in libos or pal. just returning\n");
        return 0;
    }

    struct shim_thread * thread = (struct shim_thread *) tcb->tp;
    int begin_sig = 1, end_sig = NUM_KNOWN_SIGS;

    if (sig)
        end_sig = (begin_sig = sig) + 1;

    sig = begin_sig;

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

        __handle_one_signal(tcb, sig, signal, event);
        free(signal);
        DkThreadYieldExecution();
        tcb->context.preempt &= ~SIGNAL_DELAYED;
        if (uc != NULL && event != NULL)
            return 1;
    }

    return 0;
}

void handle_sysret_signal(void)
{
    shim_tcb_t * tcb = SHIM_GET_TLS();
    struct shim_thread * thread = (struct shim_thread *) tcb->tp;
    debug("sysret signal: regs %p stack: %p "
          "thread: %p tcb: %p &flags: %p flags: 0x%x (counter = %d) stack: %p\n",
          tcb->context.regs, tcb->context.sp,
          thread, tcb, &tcb->flags, tcb->flags, thread->has_signal.counter,
          &tcb);

    clear_bit(SHIM_FLAG_SIGPENDING, &tcb->flags);
    /* This doesn't take user signal mask into account.
       peek_signal_log would be needed. not fetch_signal_log */
    if (atomic_read(&thread->has_signal))
        set_bit(SHIM_FLAG_SIGPENDING, &tcb->flags);
}

void handle_signal (bool delayed_only)
{
    shim_tcb_t * tcb = SHIM_GET_TLS();
    assert(tcb);

    struct shim_thread * thread = (struct shim_thread *) tcb->tp;

    /* Fast path */
    if (!thread || !atomic_read(&thread->has_signal))
        return;

    debug("handle signal (counter = %d)\n", atomic_read(&thread->has_signal));

    __disable_preempt(tcb);

    if ((tcb->context.preempt & ~SIGNAL_DELAYED) > 1) {
        debug("signal delayed (%d)\n", tcb->context.preempt & ~SIGNAL_DELAYED);
        tcb->context.preempt |= SIGNAL_DELAYED;
        set_bit(SHIM_FLAG_SIGPENDING, &tcb->flags);
    } else {
        if (!(delayed_only && !(tcb->context.preempt & SIGNAL_DELAYED))) {
            __handle_signal(tcb, 0, NULL, NULL);
        }
    }

    __enable_preempt(tcb);
    debug("__enable_preempt: %s:%d\n", __FILE__, __LINE__);
}

static void __setup_next_sig_frame(
    shim_tcb_t * tcb, int sig, struct shim_signal * signal,
    ucontext_t * user_uc,
    void (*handler) (int, siginfo_t *, void *), void (*restorer) (void))
{
    struct sigframe * user_sigframe = (struct sigframe*)(((void *)user_uc) - 8);

    user_sigframe->restorer = restorer;
    struct shim_regs * regs = tcb->context.regs;
    tcb->context.sp = (void *)user_sigframe;
    tcb->context.ret_ip = (void *)handler;
    regs->rdi = (unsigned long)sig;
    regs->rsi = (unsigned long)&user_sigframe->info;
    regs->rdx = (unsigned long)&user_sigframe->uc;
    tcb->context.syscall_nr = 0; // rax

    // TODO signal mask

    // TODO initialize more fp registers.
    __asm__ __volatile__("fninit\n");
}

struct sig_deliver
{
    int sig;
    struct shim_signal * signal;
    void (*handler) (int, siginfo_t *, void *);
    void (*restorer) (void);
};

static bool __get_signal_to_deliver(struct sig_deliver * deliver)
{
    deliver->signal = NULL;
    shim_tcb_t * tcb = SHIM_GET_TLS();
    struct shim_thread * thread = get_cur_thread();

    while (atomic_read(&thread->has_signal)) {
        struct shim_signal * signal = NULL;
        /* signul number starts from 1 */
        int sig;
        for (sig = 1 ; sig < NUM_KNOWN_SIGS ; sig++)
            if (!__sigismember(&thread->signal_mask, sig) &&
                (signal = fetch_signal_log(tcb, thread, sig)))
                break;

        if (!signal)
            continue;

        void (*handler) (int, siginfo_t *, void *);
        void (*restorer) (void);
        get_signal_handler(thread, sig, &handler, &restorer);
        if ((void *) handler == (void *) 1) /* SIG_IGN */
            continue;

        if (!handler && !(handler = default_sighandler[sig - 1]))
            continue;

        deliver->sig = sig;
        deliver->signal = signal;
        deliver->handler = handler;
        deliver->restorer = restorer;
        return true;
    }
    return false;
}


int handle_next_signal(ucontext_t * user_uc)
{
    struct sig_deliver deliver;
    if (__get_signal_to_deliver(&deliver)) {
        __setup_next_sig_frame(SHIM_GET_TLS(), deliver.sig, deliver.signal,
                               user_uc, deliver.handler, deliver.restorer);
        return 1;
    }
    return 0;
}

bool deliver_signal_on_sysret(void * stack,
                              uint64_t rflags, uint64_t syscall_ret)
{
    shim_tcb_t * tcb = SHIM_GET_TLS();

    struct sig_deliver deliver;
    debug("regs: %p sp: %p ip: %p stack: %p &tcb %p tcb %p\n",
          tcb->context.regs, tcb->context.sp, tcb->context.ret_ip,
          stack, &tcb, tcb);

    clear_bit(SHIM_FLAG_SIGPENDING, &tcb->flags);
    if (!__get_signal_to_deliver(&deliver)) {
        /* syscallas.S restore %rax as return value for system call */
        tcb->context.syscall_nr = syscall_ret;
        return false;
    }

    int sig = deliver.sig;
    struct shim_signal * signal = deliver.signal;
    void (*handler) (int, siginfo_t *, void *) = deliver.handler;
    void (*restorer) (void) = deliver.restorer;

    struct shim_regs * regs = stack;
    stack += sizeof(*regs);
    long * rip = stack;
    stack += sizeof(*rip);
    struct sigframe * user_sigframe = stack;
    assert(user_sigframe == ALIGN_UP_PTR(user_sigframe, 16UL));
    stack += sizeof(*user_sigframe);
    stack = ALIGN_UP_PTR(stack, 64UL);
    struct _libc_fpstate * user_fpstate = stack;

    debug("regs: %p rip: %p sigframe: %p uc: %p fpstate: %p\n",
          regs, rip, user_sigframe, &user_sigframe->uc, user_fpstate);

    /* move up context.regs on stack*/
    memcpy(regs, tcb->context.regs, sizeof(*regs));
    tcb->context.regs = regs;

    /* setup sigframe */
    user_sigframe->restorer = restorer;

    ucontext_t * user_uc = &user_sigframe->uc;
    user_uc->uc_flags = UC_FP_XSTATE;
    user_uc->uc_link = NULL;
    user_uc->uc_stack.ss_sp = 0;
    user_uc->uc_stack.ss_size = 0;
    user_uc->uc_stack.ss_flags = 0;

    gregset_t * gregs = &user_uc->uc_mcontext.gregs;
    (*gregs)[REG_R8] = regs->r8;
    (*gregs)[REG_R9] = regs->r9;
    (*gregs)[REG_R10] = regs->r10;
    (*gregs)[REG_R11] = regs->r11;
    (*gregs)[REG_R12] = regs->r12;
    (*gregs)[REG_R13] = regs->r13;
    (*gregs)[REG_R14] = regs->r14;
    (*gregs)[REG_R15] = regs->r15;
    (*gregs)[REG_RDI] = regs->rdi;
    (*gregs)[REG_RSI] = regs->rsi;
    (*gregs)[REG_RBP] = regs->rbp;
    (*gregs)[REG_RBX] = regs->rbx;
    (*gregs)[REG_RDX] = regs->rdx;
    (*gregs)[REG_RAX] = syscall_ret;
    (*gregs)[REG_RCX] = regs->rcx;
    (*gregs)[REG_RSP] = (long)tcb->context.sp;
    (*gregs)[REG_RIP] = (long)tcb->context.ret_ip;
    (*gregs)[REG_EFL] = rflags;
    union csgsfs sr = {
        .cs = 0x33, // __USER_CS(5) | 0(GDT) | 3(RPL)
        .fs = 0,
        .gs = 0,
        .ss = 0x2b, // __USER_DS(6) | 0(GDT) | 3(RPL)
    };
    (*gregs)[REG_CSGSFS] = sr.csgsfs;

    (*gregs)[REG_ERR] = signal->info.si_errno;
    (*gregs)[REG_TRAPNO] = signal->info.si_code;
    (*gregs)[REG_OLDMASK] = 0;
    (*gregs)[REG_CR2] = (long)signal->info.si_addr;

    user_uc->uc_mcontext.fpregs = user_fpstate;
    memset(user_fpstate, 0, fpu_xstate_size);

    long lmask = -1;
    long hmask = -1;
    asm volatile("xsave64 (%0)"
                 :: "r"(user_fpstate), "m"(*user_fpstate),
                  "a"(lmask), "d"(hmask)
                 : "memory");
    struct _fpx_sw_bytes * user_sw = &user_fpstate->sw_reserved;
    user_sw->magic1 = FP_XSTATE_MAGIC1;
    user_sw->extended_size = fpu_xstate_size + FP_XSTATE_MAGIC2_SIZE;
    user_sw->xstate_size = fpu_xstate_size;
    *((typeof(FP_XSTATE_MAGIC2)*)((void*)user_fpstate + user_sw->xstate_size))
        = FP_XSTATE_MAGIC2;

    // TODO initialize by XRESTORE64
    asm volatile("fninit");

    // TODO. get current sigmask and mask signal
    // XXX sigaction();
    __sigemptyset(&user_uc->uc_sigmask);

    // setup to return to signal handler
    // tcb->context.sp = (void *)user_sigframe;
    // tcb->context.ret_ip = (void *)handler;
    *rip = (long)handler;
    regs->rdi = (long)sig;
    regs->rsi = (unsigned long)&user_sigframe->info;
    regs->rdx = (unsigned long)&user_sigframe->uc;

    return true;
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

    try_process_exit(0, sig);
    DkThreadExit();
}

/* We don't currently implement core dumps, but put a wrapper
 * in case we do in the future */
static void sighandler_core (int sig, siginfo_t * info, void * ucontext)
{
    sighandler_kill(sig, info, ucontext);
}

static void (*default_sighandler[NUM_SIGS]) (int, siginfo_t *, void *) =
    {
        /* SIGHUP */    &sighandler_kill,
        /* SIGINT */    &sighandler_kill,
        /* SIGQUIT */   &sighandler_kill,
        /* SIGILL */    &sighandler_kill,
        /* SIGTRAP */   &sighandler_core,
        /* SIGABRT */   &sighandler_kill,
        /* SIGBUS */    &sighandler_kill,
        /* SIGFPE */    &sighandler_kill,
        /* SIGKILL */   &sighandler_kill,
        /* SIGUSR1 */   NULL,
        /* SIGSEGV */   &sighandler_kill,
        /* SIGUSR2 */   NULL,
        /* SIGPIPE */   &sighandler_kill,
        /* SIGALRM */   &sighandler_kill,
        /* SIGTERM */   &sighandler_kill,
        /* SIGSTKFLT */ NULL,
        /* SIGCHLD */   NULL,
        /* SIGCONT */   NULL,
        /* SIGSTOP */   NULL,
        /* SIGTSTP */   NULL,
        /* SIGTTIN */   NULL,
        /* SIGTTOU */   NULL,
    };
