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

#include <asm/signal.h>

// __rt_sighandler_t is different from __sighandler_t in <asm-generic/signal-defs.h>:
//    typedef void __signalfn_t(int);
//    typedef __signalfn_t *__sighandler_t

typedef void (*__rt_sighandler_t)(int, siginfo_t*, void*);

static __rt_sighandler_t default_sighandler[NUM_SIGS];

#define MAX_SIGNAL_LOG 32

struct shim_signal_log {
    /* FIXME: This whole structure needs a rewrite, it can't be implemented correctly lock-free. */
    /*
     * ring buffer of pending same-type signals (e.g. all pending SIGINTs).
     * [tail, head) for used area (with wrap around)
     * [head, tail) for free area (with wrap around)
     */
    struct atomic_int head;
    struct atomic_int tail;
    struct shim_signal* logs[MAX_SIGNAL_LOG];
};

struct shim_signal_log* signal_logs_alloc(void) {
    struct shim_signal_log* signal_logs = malloc(sizeof(*signal_logs) * NUM_SIGS);
    if (!signal_logs)
        return NULL;
    for (int sig = 0; sig < NUM_SIGS; sig++) {
        atomic_set(&signal_logs[sig].head, 0);
        atomic_set(&signal_logs[sig].tail, 0);
    }
    return signal_logs;
}

void signal_logs_free(struct shim_signal_log* signal_logs) {
    for (int sig = 0; sig < NUM_SIGS; sig++) {
        struct shim_signal_log* log = &signal_logs[sig];
        int tail = atomic_read(&log->tail);
        int head = atomic_read(&log->head);
        if (head < tail) {
            for (int i = tail; i < MAX_SIGNAL_LOG; i++) {
                free(log->logs[i]);
            }
            tail = 0;
        }
        for (int i = tail; i < head; i++) {
            free(log->logs[i]);
        }
    }
    free(signal_logs);
}

bool signal_logs_pending(const struct shim_signal_log* signal_log, int sig) {
    /* FIXME: race condition between reading two atomic variables */
    return atomic_read(&signal_log[sig - 1].tail) != atomic_read(&signal_log[sig - 1].head);
}

static struct shim_signal **
allocate_signal_log (struct shim_thread * thread, int sig)
{
    if (!thread->signal_logs)
        return NULL;

    struct shim_signal_log * log = &thread->signal_logs[sig - 1];
    int tail, head, old_head;

    /* FIXME: race condition between allocating the slot and populating the slot. */
    do {
        tail = atomic_read(&log->tail);
        old_head = head = atomic_read(&log->head);

        if (tail == head + 1 || (!tail && head == (MAX_SIGNAL_LOG - 1)))
            return NULL;

        head = (head == MAX_SIGNAL_LOG - 1) ? 0 : head + 1;
    } while (atomic_cmpxchg(&log->head, old_head, head) == head);

    debug("signal_logs[%d]: tail=%d, head=%d (counter = %ld)\n", sig - 1,
          tail, head, thread->has_signal.counter + 1);

    atomic_inc(&thread->has_signal);

    return &log->logs[old_head];
}

static struct shim_signal *
fetch_signal_log (struct shim_thread * thread, int sig)
{
    struct shim_signal_log * log = &thread->signal_logs[sig - 1];
    struct shim_signal * signal = NULL;
    int tail, head, old_tail;

    /* FIXME: race condition between finding the slot and clearing the slot. */
    while (1) {
        old_tail = tail = atomic_read(&log->tail);
        head = atomic_read(&log->head);

        if (tail == head)
            return NULL;

        if (!(signal = log->logs[tail]))
            return NULL;

        log->logs[tail] = NULL;
        tail = (tail == MAX_SIGNAL_LOG - 1) ? 0 : tail + 1;

        if (atomic_cmpxchg(&log->tail, old_tail, tail) == old_tail)
            break;

        log->logs[old_tail] = signal;
    }

    debug("signal_logs[%d]: tail=%d, head=%d\n", sig -1, tail, head);

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

    if (tcb && tcb->context.regs && tcb->context.regs->orig_rax) {
        struct shim_context * ct = &tcb->context;

        if (ct->regs) {
            struct shim_regs * regs = ct->regs;
            context->uc_mcontext.gregs[REG_RIP] = regs->rip;
            context->uc_mcontext.gregs[REG_EFL] = regs->rflags;
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
            context->uc_mcontext.gregs[REG_RSP] = regs->rsp;
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
    shim_tcb_t * tcb = shim_get_tcb();
    assert(tcb);

    // Signals should not be delivered before the user process starts
    // or after the user process dies.
    if (!tcb->tp || !cur_thread_is_alive())
        return;

    struct shim_thread * cur_thread = (struct shim_thread *) tcb->tp;
    int sig = info->si_signo;

    int64_t preempt = __disable_preempt(tcb);

    struct shim_signal * signal = __alloca(sizeof(struct shim_signal));
    /* save in signal */
    memset(signal, 0, sizeof(struct shim_signal));
    __store_info(info, signal);
    __store_context(tcb, context, signal);
    signal->pal_context = context;

    if (preempt > 1 ||
        __sigismember(&cur_thread->signal_mask, sig)) {
        struct shim_signal ** signal_log = NULL;
        if ((signal = malloc_copy(signal,sizeof(struct shim_signal))) &&
            (signal_log = allocate_signal_log(cur_thread, sig))) {
            *signal_log = signal;
        }
        if (signal && !signal_log) {
            SYS_PRINTF("signal queue is full (TID = %u, SIG = %d)\n",
                       tcb->tid, sig);
            free(signal);
        }
    } else {
        __handle_signal(tcb, sig);
        __handle_one_signal(tcb, sig, signal);
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

static inline bool context_is_internal(PAL_CONTEXT * context)
{
    return context &&
        (void *) context->IP >= (void *) &__code_address &&
        (void *) context->IP < (void *) &__code_address_end;
}

static inline void internal_fault(const char* errstr,
                                  PAL_NUM addr, PAL_CONTEXT * context)
{
    IDTYPE tid = get_cur_tid();
    if (context_is_internal(context))
        SYS_PRINTF("%s at 0x%08lx (IP = +0x%lx, VMID = %u, TID = %u)\n", errstr,
                   addr, (void *) context->IP - (void *) &__load_address,
                   cur_process.vmid, is_internal_tid(tid) ? 0 : tid);
    else
        SYS_PRINTF("%s at 0x%08lx (IP = 0x%08lx, VMID = %u, TID = %u)\n", errstr,
                   addr, context ? context->IP : 0,
                   cur_process.vmid, is_internal_tid(tid) ? 0 : tid);

    PAUSE();
}

static void arithmetic_error_upcall (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    if (is_internal_tid(get_cur_tid()) || context_is_internal(context)) {
        internal_fault("Internal arithmetic fault", arg, context);
    } else {
        if (context)
            debug("arithmetic fault at 0x%08lx\n", context->IP);

        deliver_signal(ALLOC_SIGINFO(SIGFPE, FPE_INTDIV,
                                     si_addr, (void *) arg), context);
    }
    DkExceptionReturn(event);
}

static void memfault_upcall (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    shim_tcb_t * tcb = shim_get_tcb();
    assert(tcb);

    if (tcb->test_range.cont_addr
        && (void *) arg >= tcb->test_range.start
        && (void *) arg <= tcb->test_range.end) {
        assert(context);
        tcb->test_range.has_fault = true;
        context->rip = (PAL_NUM) tcb->test_range.cont_addr;
        goto ret_exception;
    }

    if (is_internal_tid(get_cur_tid()) || context_is_internal(context)) {
        internal_fault("Internal memory fault", arg, context);
        goto ret_exception;
    }

    if (context)
        debug("memory fault at 0x%08lx (IP = 0x%08lx)\n", arg, context->IP);

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
            uintptr_t eof_in_vma = (uintptr_t) vma.addr + vma.offset + vma.file->info.file.size;
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

    deliver_signal(ALLOC_SIGINFO(signo, code, si_addr, (void *) arg), context);

ret_exception:
    DkExceptionReturn(event);
}

/*
 * Helper function for test_user_memory / test_user_string; they behave
 * differently for different PALs:
 *
 * - For Linux-SGX, the faulting address is not propagated in memfault
 *   exception (SGX v1 does not write address in SSA frame, SGX v2 writes
 *   it only at a granularity of 4K pages). Thus, we cannot rely on
 *   exception handling to compare against tcb.test_range.start/end.
 *   Instead, traverse VMAs to see if [addr, addr+size) is addressable;
 *   before traversing VMAs, grab a VMA lock.
 *
 * - For other PALs, we touch one byte of each page in [addr, addr+size).
 *   If some byte is not addressable, exception is raised. memfault_upcall
 *   handles this exception and resumes execution from ret_fault.
 *
 * The second option is faster in fault-free case but cannot be used under
 * SGX PAL. We use the best option for each PAL for now. */
static bool is_sgx_pal(void) {
    static struct atomic_int sgx_pal = { .counter = 0 };
    static struct atomic_int inited  = { .counter = 0 };

    if (!atomic_read(&inited)) {
        /* Ensure that is_sgx_pal is updated before initialized */
        atomic_set(&sgx_pal, !strcmp_static(PAL_CB(host_type), "Linux-SGX"));
        MB();
        atomic_set(&inited, 1);
    }
    MB();

    return atomic_read(&sgx_pal) != 0;
}

/*
 * 'test_user_memory' and 'test_user_string' are helper functions for testing
 * if a user-given buffer or data structure is readable / writable (according
 * to the system call semantics). If the memory test fails, the system call
 * should return -EFAULT or -EINVAL accordingly. These helper functions cannot
 * guarantee further corruption of the buffer, or if the buffer is unmapped
 * with a concurrent system call. The purpose of these functions is simply for
 * the compatibility with programs that rely on the error numbers, such as the
 * LTP test suite. */
bool test_user_memory (void * addr, size_t size, bool write)
{
    if (!size)
        return false;

    if (!access_ok(addr, size))
        return true;

    /* SGX path: check if [addr, addr+size) is addressable (in some VMA) */
    if (is_sgx_pal())
        return !is_in_adjacent_vmas(addr, size);

    /* Non-SGX path: check if [addr, addr+size) is addressable by touching
     * a byte of each page; invalid access will be caught in memfault_upcall */
    shim_tcb_t * tcb = shim_get_tcb();
    assert(tcb && tcb->tp);
    __disable_preempt(tcb);

    /* Add the memory region to the watch list. This is not racy because
     * each thread has its own record. */
    assert(!tcb->test_range.cont_addr);
    tcb->test_range.has_fault = false;
    tcb->test_range.cont_addr = &&ret_fault;
    tcb->test_range.start = addr;
    tcb->test_range.end   = addr + size - 1;
    /* enforce compiler to store tcb->test_range into memory */
    __asm__ volatile(""::: "memory");

    /* Try to read or write into one byte inside each page */
    void * tmp = addr;
    while (tmp <= addr + size - 1) {
        if (write) {
            *(volatile char *) tmp = *(volatile char *) tmp;
        } else {
            *(volatile char *) tmp;
        }
        tmp = ALLOC_ALIGN_UP_PTR(tmp + 1);
    }

ret_fault:
    /* enforce compiler to load tcb->test_range.has_fault below */
    __asm__ volatile("": "=m"(tcb->test_range.has_fault));

    /* If any read or write into the target region causes an exception,
     * the control flow will immediately jump to here. */
    bool has_fault = tcb->test_range.has_fault;
    tcb->test_range.has_fault = false;
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
    if (!access_ok(addr, 1))
        return true;

    size_t size, maxlen;
    const char* next = ALLOC_ALIGN_UP_PTR(addr + 1);

    /* SGX path: check if [addr, addr+size) is addressable (in some VMA). */
    if (is_sgx_pal()) {
        /* We don't know length but using unprotected strlen() is dangerous
         * so we check string in chunks of 4K pages. */
        do {
            maxlen = next - addr;

            if (!access_ok(addr, maxlen) || !is_in_adjacent_vmas((void*) addr, maxlen))
                return true;

            size = strnlen(addr, maxlen);
            addr = next;
            next = ALLOC_ALIGN_UP_PTR(addr + 1);
        } while (size == maxlen);

        return false;
    }

    /* Non-SGX path: check if [addr, addr+size) is addressable by touching
     * a byte of each page; invalid access will be caught in memfault_upcall. */
    shim_tcb_t * tcb = shim_get_tcb();
    assert(tcb && tcb->tp);
    __disable_preempt(tcb);

    assert(!tcb->test_range.cont_addr);
    tcb->test_range.has_fault = false;
    tcb->test_range.cont_addr = &&ret_fault;
    /* enforce compiler to store tcb->test_range into memory */
    __asm__ volatile(""::: "memory");

    do {
        /* Add the memory region to the watch list. This is not racy because
         * each thread has its own record. */
        tcb->test_range.start = (void *) addr;
        tcb->test_range.end = (void *) (next - 1);

        maxlen = next - addr;

        if (!access_ok(addr, maxlen))
            return true;
        *(volatile char *) addr; /* try to read one byte from the page */

        size = strnlen(addr, maxlen);
        addr = next;
        next = ALLOC_ALIGN_UP_PTR(addr + 1);
    } while (size == maxlen);

ret_fault:
    /* enforce compiler to load tcb->test_range.has_fault below */
    __asm__ volatile("": "=m"(tcb->test_range.has_fault));

    /* If any read or write into the target region causes an exception,
     * the control flow will immediately jump to here. */
    bool has_fault = tcb->test_range.has_fault;
    tcb->test_range.has_fault = false;
    tcb->test_range.cont_addr = NULL;
    tcb->test_range.start = tcb->test_range.end = NULL;
    __enable_preempt(tcb);
    return has_fault;
}

void __attribute__((weak)) syscall_wrapper(void)
{
    /*
     * work around for link.
     * syscalldb.S is excluded for libsysdb_debug.so so it fails to link
     * due to missing syscall_wrapper.
     */
}

static void illegal_upcall (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    struct shim_vma_val vma;

    if (!is_internal_tid(get_cur_tid()) &&
        !context_is_internal(context) &&
        !(lookup_vma((void *) arg, &vma)) &&
        !(vma.flags & VMA_INTERNAL)) {

        assert(context);
        debug("illegal instruction at 0x%08lx\n", context->IP);

        uint8_t * rip = (uint8_t*)context->IP;
        /*
         * Emulate syscall instruction (opcode 0x0f 0x05);
         * syscall instruction is prohibited in
         *   Linux-SGX PAL and raises a SIGILL exception and
         *   Linux PAL with seccomp and raise SIGSYS exception.
         */
#if 0
        if (rip[-2] == 0x0f && rip[-1] == 0x05) {
            /* TODO: once finished, remove "#if 0" above. */
            /*
             * SIGSYS case (can happen with Linux PAL with seccomp)
             * rip points to the address after syscall instruction
             * %rcx: syscall instruction must put an
             *       instruction-after-syscall in rcx
             */
            context->rax = siginfo->si_syscall; /* PAL_CONTEXT doesn't
                                                 * include a member
                                                 * corresponding to
                                                 * siginfo_t::si_syscall yet.
                                                 */
            context->rcx = (long)rip;
            context->r11 = context->efl;
            context->rip = (long)&syscall_wrapper;
        } else
#endif
        if (rip[0] == 0x0f && rip[1] == 0x05) {
            /*
             * SIGILL case (can happen in Linux-SGX PAL)
             * %rcx: syscall instruction must put an instruction-after-syscall
             *       in rcx. See the syscall_wrapper in syscallas.S
             * TODO: check SIGILL and ILL_ILLOPN
             */
            context->rcx = (long)rip + 2;
            context->r11 = context->efl;
            context->rip = (long)&syscall_wrapper;
        } else {
            deliver_signal(ALLOC_SIGINFO(SIGILL, ILL_ILLOPC,
                                         si_addr, (void *) arg), context);
        }
    } else {
        internal_fault("Internal illegal fault", arg, context);
    }
    DkExceptionReturn(event);
}

static void quit_upcall (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    __UNUSED(arg);
    __UNUSED(context);
    if (!is_internal_tid(get_cur_tid())) {
        deliver_signal(ALLOC_SIGINFO(SIGTERM, SI_USER, si_pid, 0), NULL);
    }
    DkExceptionReturn(event);
}

static void suspend_upcall (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    __UNUSED(arg);
    __UNUSED(context);
    if (!is_internal_tid(get_cur_tid())) {
        deliver_signal(ALLOC_SIGINFO(SIGINT, SI_USER, si_pid, 0), NULL);
    }
    DkExceptionReturn(event);
}

static void resume_upcall (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    __UNUSED(arg);
    __UNUSED(context);
    shim_tcb_t * tcb = shim_get_tcb();
    if (!tcb || !tcb->tp)
        return;

    if (!is_internal_tid(get_cur_tid())) {
        int64_t preempt = __disable_preempt(tcb);
        if (preempt <= 1)
            __handle_signal(tcb, 0);
        __enable_preempt(tcb);
    }
    DkExceptionReturn(event);
}

int init_signal (void)
{
    DkSetExceptionHandler(&arithmetic_error_upcall,     PAL_EVENT_ARITHMETIC_ERROR);
    DkSetExceptionHandler(&memfault_upcall,    PAL_EVENT_MEMFAULT);
    DkSetExceptionHandler(&illegal_upcall,     PAL_EVENT_ILLEGAL);
    DkSetExceptionHandler(&quit_upcall,        PAL_EVENT_QUIT);
    DkSetExceptionHandler(&suspend_upcall,     PAL_EVENT_SUSPEND);
    DkSetExceptionHandler(&resume_upcall,      PAL_EVENT_RESUME);
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

    if (set) {
        memcpy(&thread->signal_mask, set, sizeof(__sigset_t));

        /* SIGKILL and SIGSTOP cannot be ignored */
        __sigdelset(&thread->signal_mask, SIGKILL);
        __sigdelset(&thread->signal_mask, SIGSTOP);
    }

    return &thread->signal_mask;
}

static __rt_sighandler_t __get_sighandler(struct shim_thread* thread, int sig) {
    assert(locked(&thread->lock));

    struct shim_signal_handle* sighdl = &thread->signal_handles[sig - 1];
    __rt_sighandler_t handler = NULL;

    if (sighdl->action) {
        struct __kernel_sigaction * act = sighdl->action;
        /*
         * on amd64, sa_handler can be treated as sa_sigaction
         * because 1-3 arguments are passed by register and
         * sa_handler simply ignores 2nd and 3rd argument.
         */
#ifdef __i386__
# error "x86-32 support is heavily broken."
#endif
        handler = (void*)act->k_sa_handler;
        if (act->sa_flags & SA_RESETHAND) {
            sighdl->action = NULL;
            free(act);
        }
    }

    if ((void*)handler == SIG_IGN)
        return NULL;

    return handler ? : default_sighandler[sig - 1];
}

static void
__handle_one_signal(shim_tcb_t* tcb, int sig, struct shim_signal* signal) {
    struct shim_thread* thread = (struct shim_thread*)tcb->tp;
    __rt_sighandler_t handler = NULL;

    if (signal->info.si_signo == SIGCP) {
        join_checkpoint(thread, SI_CP_SESSION(&signal->info));
        return;
    }

    lock(&thread->lock);
    handler = __get_sighandler(thread, sig);
    unlock(&thread->lock);

    if (!handler)
        return;

    debug("%s handled\n", signal_name(sig));

    // If the context is never stored in the signal, it means the signal is handled during
    // system calls, and before the thread is resumed.
    if (!signal->context_stored)
        __store_context(tcb, NULL, signal);

    struct shim_context * context = NULL;

    if (tcb->context.regs && tcb->context.regs->orig_rax) {
        context = __alloca(sizeof(struct shim_context));
        memcpy(context, &tcb->context, sizeof(struct shim_context));
        tcb->context.regs->orig_rax = 0;
        tcb->context.next = context;
    }

    debug("run signal handler %p (%d, %p, %p)\n", handler, sig, &signal->info,
          &signal->context);

    (*handler) (sig, &signal->info, &signal->context);

    if (context)
        memcpy(&tcb->context, context, sizeof(struct shim_context));

    if (signal->pal_context)
        memcpy(signal->pal_context, signal->context.uc_mcontext.gregs, sizeof(PAL_CONTEXT));
}

void __handle_signal (shim_tcb_t * tcb, int sig)
{
    struct shim_thread * thread = tcb->tp;
    assert(thread);
    int begin_sig = 1, end_sig = NUM_KNOWN_SIGS;

    if (sig)
        end_sig = (begin_sig = sig) + 1;

    sig = begin_sig;

    while (atomic_read(&thread->has_signal)) {
        struct shim_signal * signal = NULL;

        for ( ; sig < end_sig ; sig++)
            if (!__sigismember(&thread->signal_mask, sig) &&
                (signal = fetch_signal_log(thread, sig)))
                break;

        if (!signal)
            break;

        if (!signal->context_stored)
            __store_context(tcb, NULL, signal);

        __handle_one_signal(tcb, sig, signal);
        free(signal);
        DkThreadYieldExecution();
    }
}

void handle_signal (void)
{
    shim_tcb_t * tcb = shim_get_tcb();
    assert(tcb);

    struct shim_thread * thread = (struct shim_thread *) tcb->tp;

    /* Fast path */
    if (!thread || !thread->has_signal.counter)
        return;

    int64_t preempt = __disable_preempt(tcb);

    if (preempt > 1)
        debug("signal delayed (%ld)\n", preempt);
    else
        __handle_signal(tcb, 0);

    __enable_preempt(tcb);
    debug("__enable_preempt: %s:%d\n", __FILE__, __LINE__);
}

// Need to hold thread->lock when calling this function
void append_signal(struct shim_thread* thread, int sig, siginfo_t* info, bool need_interrupt) {
    assert(locked(&thread->lock));

    __rt_sighandler_t handler = __get_sighandler(thread, sig);

    if (!handler) {
        // SIGSTOP and SIGKILL cannot be ignored
        assert(sig != SIGSTOP && sig != SIGKILL);
        /*
         * If signal is ignored and unmasked, the signal can be discarded
         * directly. Otherwise it causes memory leak.
         *
         * SIGCHLD can be discarded even if it's masked.
         * For Linux implementation, please refer to
         * do_notify_parent() in linux/kernel/signal.c
         * For standard, please refer to
         * https://pubs.opengroup.org/onlinepubs/9699919799/functions/_Exit.html
         */
        if (!__sigismember(&thread->signal_mask, sig) || sig == SIGCHLD)
            return;

        // If a signal is set to be ignored, append the signal but don't interrupt the thread
        need_interrupt = false;
    }

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
        if (need_interrupt) {
            debug("resuming thread %u\n", thread->tid);
            thread_wakeup(thread);
            DkThreadResume(thread->pal_handle);
        }
    } else {
        SYS_PRINTF("signal queue is full (TID = %u, SIG = %d)\n",
                   thread->tid, sig);
        free(signal);
    }
}

#define __WCOREDUMP_BIT 0x80

static void sighandler_kill (int sig, siginfo_t * info, void * ucontext)
{
    struct shim_thread* cur_thread = get_cur_thread();
    int sig_without_coredump_bit   = sig & ~(__WCOREDUMP_BIT);

    __UNUSED(ucontext);
    debug("killed by %s\n", signal_name(sig_without_coredump_bit));

    if (sig_without_coredump_bit == SIGABRT ||
        (!info->si_pid && /* signal is sent from host OS, not from another process */
         (sig_without_coredump_bit == SIGTERM || sig_without_coredump_bit == SIGINT))) {
        /* Received signal to kill the process:
         *   - SIGABRT must always kill the whole process (even if sent by Graphene itself),
         *   - SIGTERM/SIGINT must kill the whole process if signal sent from host OS. */

        /* If several signals arrive simultaneously, only one signal proceeds past this
         * point. For more information, see shim_do_exit_group(). */
        static struct atomic_int first = ATOMIC_INIT(0);
        if (atomic_cmpxchg(&first, 0, 1) == 1) {
            while (1)
                DkThreadYieldExecution();
        }

        do_kill_proc(cur_thread->tgid, cur_thread->tgid, SIGKILL, false);

        /* Ensure that the current thread wins in setting the process code/signal.
         * For more information, see shim_do_exit_group(). */
        while (check_last_thread(cur_thread)) {
            DkThreadYieldExecution();
        }
    }

    thread_or_process_exit(0, sig);
}

static void sighandler_core (int sig, siginfo_t * info, void * ucontext)
{
    /* NOTE: This implementation only indicates the core dump for wait4()
     *       and friends. No actual core-dump file is created. */
    sig = __WCOREDUMP_BIT | sig;
    sighandler_kill(sig, info, ucontext);
}

static __rt_sighandler_t default_sighandler[NUM_SIGS] = {
        /* SIGHUP */    &sighandler_kill,
        /* SIGINT */    &sighandler_kill,
        /* SIGQUIT */   &sighandler_core,
        /* SIGILL */    &sighandler_core,
        /* SIGTRAP */   &sighandler_core,
        /* SIGABRT */   &sighandler_core,
        /* SIGBUS */    &sighandler_core,
        /* SIGFPE */    &sighandler_core,
        /* SIGKILL */   &sighandler_kill,
        /* SIGUSR1 */   &sighandler_kill,
        /* SIGSEGV */   &sighandler_core,
        /* SIGUSR2 */   &sighandler_kill,
        /* SIGPIPE */   &sighandler_kill,
        /* SIGALRM */   &sighandler_kill,
        /* SIGTERM */   &sighandler_kill,
        /* SIGSTKFLT */ &sighandler_kill,
        /* SIGCHLD */   NULL,
        /* SIGCONT */   NULL,
        /* SIGSTOP */   NULL,
        /* SIGTSTP */   NULL,
        /* SIGTTIN */   NULL,
        /* SIGTTOU */   NULL,
        /* SIGURG  */   NULL,
        /* SIGXCPU */   &sighandler_core,
        /* SIGXFSZ */   &sighandler_core,
        /* SIGVTALRM */ &sighandler_kill,
        /* SIGPROF   */ &sighandler_kill,
        /* SIGWINCH  */ NULL,
        /* SIGIO   */   &sighandler_kill,
        /* SIGPWR  */   &sighandler_kill,
        /* SIGSYS  */   &sighandler_core
    };
