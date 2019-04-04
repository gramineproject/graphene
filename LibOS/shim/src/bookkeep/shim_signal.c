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

static void __handle_signal(shim_tcb_t * tcb, int sig, PAL_CONTEXT* context);

// __rt_sighandler_t is different from __sighandler_t in <asm-generic/signal-defs.h>:
//    typedef void __signalfn_t(int);
//    typedef __signalfn_t *__sighandler_t

typedef void (*__rt_sighandler_t)(int, siginfo_t*, void*);
typedef void (*restorer_t)(void);

static __rt_sighandler_t default_sighandler[NUM_SIGS];

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

    debug("signal_logs[%d]: head=%d, tail=%d (counter = %ld)\n", sig - 1,
          head, tail, thread->has_signal.counter + 1);

    atomic_inc(&thread->has_signal);
    set_bit(SHIM_FLAG_SIGPENDING, &thread->shim_tcb->flags);

    return &log->logs[old_tail];
}

static struct shim_signal *
fetch_signal_log (struct shim_thread * thread, int sig)
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
__handle_one_signal(shim_tcb_t* tcb, int sig, struct shim_signal* signal, PAL_CONTEXT* context);

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

#ifdef __x86_64__
#define IP rip
#else
#define IP eip
#endif

static inline bool DkInPal(PAL_CONTEXT* context) {
    return context &&
        PAL_CB(pal_text.start) <= (void*) context->IP &&
        (void*) context->IP < PAL_CB(pal_text.end);
}

static inline bool context_is_internal(PAL_CONTEXT * context)
{
    return context &&
        (void *) context->IP >= (void *) &__code_address &&
        (void *) context->IP < (void *) &__code_address_end;
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

    struct shim_signal* signal = malloc(sizeof(*signal));
    if (!signal) {
        return;
    }

    int64_t preempt = __disable_preempt(tcb);

    /* save in signal */
    memset(signal, 0, sizeof(struct shim_signal));
    __store_info(info, signal);
    __store_context(tcb, context, signal);
    signal->pal_context = context;

    if (preempt > 1 || context == NULL ||
        context_is_internal(context) || DkInPal(context) ||
        __sigismember(&cur_thread->signal_mask, sig)) {
        struct shim_signal** signal_log = allocate_signal_log(cur_thread, sig);
        if (signal_log) {
            *signal_log = signal;
        } else {
            SYS_PRINTF("signal queue is full (TID = %u, SIG = %d)\n",
                       tcb->tid, sig);
            free(signal);
        }
    } else {
        __handle_signal(tcb, sig, context);
        __handle_one_signal(tcb, sig, signal, context);
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
    if (is_internal_tid(get_cur_tid()) || context_is_internal(context) ||
        DkInPal(context)) {
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

    if (is_internal_tid(get_cur_tid()) || context_is_internal(context) ||
        DkInPal(context)) {
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

static void illegal_upcall (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    struct shim_vma_val vma;

    if (!is_internal_tid(get_cur_tid()) &&
        !context_is_internal(context) &&
        !DkInPal(context) &&
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

/*
 * workaround for link syscalldb_debug.so
 * syscalldb.S is excluded from libsysdb_debug.so so it fails to link
 * due to missing symbols.
 */
void* __syscallas_return_begin __attribute__((weak)) = NULL;
void* __syscallas_return_before_jmp __attribute__((weak)) = NULL;
void* __syscallas_return_end __attribute__((weak)) = NULL;
void* __syscalldb_check_sigpending_begin __attribute__((weak)) = NULL;
void* __syscalldb_check_sigpending_end __attribute__((weak)) = NULL;

void __attribute__((weak)) syscall_wrapper(void) {
}

void __attribute__((weak)) syscalldb_check_sigpending(void) {
}

static void syscallas_return_emulate(PAL_CONTEXT* context) {
    if (!context) {
        return;
    }

    /* see syscallas.S
     * Emulate returning to app.
     * We've past the last check of signal pending, but still in LibOS.
     * Emulate last instructions returning to app so that it's in app.
     * Then we can handle async signal safely.
     */
    void* rip = (void *)context->IP;
    if (rip == (void*)&__syscallas_return_before_jmp) {
        // emulate jmp *r11
        shim_tcb_t* tcb = shim_get_tcb();
        assert(tcb->context.regs == NULL);
        context->rip = tcb->tmp_rip;
    } else if ((void*)&__syscallas_return_begin <= rip &&
        rip <= (void*)&__syscallas_return_end) {
        // emulate __syscallas_return_begin to __syscallas_return_end
        shim_tcb_t* tcb = shim_get_tcb();
        assert(tcb);

        struct shim_regs* regs = tcb->context.regs;
        assert(regs);
        tcb->context.regs = NULL;

        context->r15 = regs->r15;
        context->r14 = regs->r14;
        context->r13 = regs->r13;
        context->r12 = regs->r12;
        context->r11 = regs->r11;
        context->r10 = regs->r10;
        context->r9 = regs->r9;
        context->r8 = regs->r8;
        context->rcx = regs->rcx;
        context->rdx = regs->rdx;
        context->rsi = regs->rsi;
        context->rdi = regs->rdi;
        context->rbx = regs->rbx;
        context->rbp = regs->rbp;
        context->efl = regs->rflags;
        context->rsp = regs->rsp;
        context->rip = regs->rip;
    } else if ((void*)&__syscalldb_check_sigpending_begin <= rip &&
               rip <= (void*)&__syscalldb_check_sigpending_end) {
        /*
         * emulate ret instruction.
         * As we'll deliver signal, sigpending check in
         * syscalldb_check_sigpending can be safely skipped.
         */
        uint64_t* rsp = (uint64_t*)context->rsp;
        context->rip = *rsp;
        rsp++;
        context->rsp = (uint64_t)rsp;
    }
}

static void quit_upcall (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    __UNUSED(arg);
    syscallas_return_emulate(context);
    if (!is_internal_tid(get_cur_tid())) {
        deliver_signal(ALLOC_SIGINFO(SIGTERM, SI_USER, si_pid, 0), context);
    }
    DkExceptionReturn(event);
}

static void suspend_upcall (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    __UNUSED(arg);
    syscallas_return_emulate(context);
    if (!is_internal_tid(get_cur_tid())) {
        deliver_signal(ALLOC_SIGINFO(SIGINT, SI_USER, si_pid, 0), context);
    }
    DkExceptionReturn(event);
}

static void resume_upcall (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    __UNUSED(arg);
    shim_tcb_t * tcb = shim_get_tcb();
    if (!tcb || !tcb->tp)
        return;

    syscallas_return_emulate(context);
    if (!is_internal_tid(get_cur_tid())) {
        int64_t preempt = __disable_preempt(tcb);
        if (preempt <= 1)
            __handle_signal(tcb, 0, context);
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

static void get_signal_handler(struct shim_thread * thread, int sig,
                               __rt_sighandler_t* handler,
                               restorer_t* restorer)
{
    *handler = NULL;
    *restorer = NULL;

    lock(&thread->lock);

    struct shim_signal_handle* sighdl = &thread->signal_handles[sig - 1];
    struct __kernel_sigaction* act = NULL;
    if (sighdl->action) {
        act = sighdl->action;
        *handler = (void*)act->k_sa_handler;
        *restorer = act->sa_restorer;
        if (act->sa_flags & SA_RESETHAND) {
            sighdl->action = NULL;
        } else {
            act = NULL;
        }
    }

    unlock(&thread->lock);

    free(act);
    if ((void*)handler == SIG_IGN) {
        *handler = NULL;
    } else if (!*handler) {
        *handler = default_sighandler[sig - 1];
    }
}

static unsigned int fpstate_size_get(const struct _libc_fpstate* fpstate) {
    if (fpstate == NULL)
        return 0;

    const struct _fpx_sw_bytes* sw = &fpstate->sw_reserved;
    if (sw->magic1 == FP_XSTATE_MAGIC1 &&
        sw->xstate_size < sw->extended_size &&
        *((__typeof__(FP_XSTATE_MAGIC2)*)((void*)fpstate + sw->xstate_size)) ==
        FP_XSTATE_MAGIC2)
        return sw->extended_size;

    return sizeof(struct swregs_state);
}

static void direct_call_if_default_handler(
    int sig, siginfo_t* info, __rt_sighandler_t handler);

static void* __get_signal_stack(struct shim_thread* thread, void* current_stack) {
    const stack_t* ss = &thread->signal_altstack;
    if (ss->ss_flags & SS_DISABLE)
        return current_stack - RED_ZONE_SIZE;
    if (ss->ss_sp < current_stack && current_stack <= ss->ss_sp + ss->ss_size)
        return current_stack - RED_ZONE_SIZE;

    return ss->ss_sp + ss->ss_size;
}

static void* aligndown_sigframe(void* sp) {
    return ALIGN_DOWN_PTR(sp, 16UL) - 8;
}

static void __setup_sig_frame(
    shim_tcb_t* tcb, int sig, struct shim_signal* signal, PAL_CONTEXT* context,
    __rt_sighandler_t handler, restorer_t restorer) {
    __UNUSED(tcb);
    direct_call_if_default_handler(sig, &signal->info, handler);

    struct _libc_xregs_state* xregs_state =
        (struct _libc_xregs_state* )context->fpregs;
    struct _libc_fpstate* fpstate = &xregs_state->fpstate;
    unsigned int fpstate_size = fpstate_size_get(fpstate);

    void* sp = __get_signal_stack(tcb->tp, (void*)context->rsp);
    fpregset_t user_fp = ALIGN_DOWN_PTR(sp - fpstate_size, 64UL);
    struct sigframe* user_sigframe =
        aligndown_sigframe((void*)user_fp - sizeof(struct sigframe));
    assert(&user_sigframe->uc == ALIGN_UP_PTR(&user_sigframe->uc, 16UL));
    user_sigframe->restorer = restorer;
    user_sigframe->uc.uc_flags = UC_SIGCONTEXT_SS | UC_STRICT_RESTORE_SS;
    user_sigframe->uc.uc_link = NULL;
    /* the layout of PAL_CONTEXT is same to gregs */
    memcpy(&user_sigframe->uc.uc_mcontext.gregs, context,
           sizeof(user_sigframe->uc.uc_mcontext.gregs));

    stack_t* stack = &user_sigframe->uc.uc_stack;
    *stack = tcb->tp->signal_altstack;

    memcpy(&user_sigframe->info, &signal->info, sizeof(signal->info));
    if (fpstate_size > 0) {
        user_sigframe->uc.uc_flags |= UC_FP_XSTATE;
        memcpy(user_fp, fpstate, fpstate_size);
        user_sigframe->uc.uc_mcontext.fpregs = user_fp;
    } else {
        user_sigframe->uc.uc_flags &= ~UC_FP_XSTATE;
        user_sigframe->uc.uc_mcontext.fpregs = NULL;
    }

    context->rsp = (long)user_sigframe;
    context->rip = (long)handler;
    context->rdi = (long)signal->info.si_signo;
    context->rsi = (long)&user_sigframe->info;
    context->rdx = (long)&user_sigframe->uc;
    context->rax = 0;
    context->fpregs = NULL;

    debug("deliver signal handler to user stack %p (%d, %p, %p) sigframe: %p uc: %p fpstate %p\n",
          handler, sig, &signal->info, &signal->context,
          user_sigframe, &user_sigframe->uc,
          user_sigframe->uc.uc_mcontext.fpregs);
}

static void
__handle_one_signal(shim_tcb_t* tcb, int sig, struct shim_signal* signal, PAL_CONTEXT* context) {
    struct shim_thread* thread = (struct shim_thread*)tcb->tp;
    __rt_sighandler_t handler = NULL;
    restorer_t restorer = NULL;

    if (signal->info.si_signo == SIGCP) {
        join_checkpoint(thread, SI_CP_SESSION(&signal->info));
        return;
    }

    debug("%s handling\n", signal_name(sig));
    /*
     * check if we're in LibOS or Pal before get_signal_handler() which
     * acquires thread->lock. It may cause deadlock if we tries to lock
     * from host signal handler.
     */
    if (context == NULL || context_is_internal(context) || DkInPal(context)) {
        /*
         * host signal handler is called during PAL or LibOS.
         * It means thread is in systeam call emulation. actual signal
         * delivery is done by deliver_signal_on_sysret()
         */
        debug("appending signal for trigger syscall return  "
              "%p (%d, %p, %p)\n", handler, sig, &signal->info,
              &signal->context);
        struct shim_signal** signal_log = allocate_signal_log(thread, sig);
        if (signal_log) {
            *signal_log = signal;
        }
        return;
    }

    get_signal_handler(thread, sig, &handler, &restorer);
    if (!handler)
        return;

    debug("%s handled\n", signal_name(sig));

    // If the context is never stored in the signal, it means the signal is handled during
    // system calls, and before the thread is resumed.
    if (!signal->context_stored)
        __store_context(tcb, NULL, signal);

    /*
     * host signal arrived while application is running.
     * setup signal frame on app stack and return back to app signal handler
     * thourgh host sigreturn.
     */
    __setup_sig_frame(tcb, sig, signal, context, handler, restorer);
}

static void __handle_signal(shim_tcb_t * tcb, int sig, PAL_CONTEXT* context) {
    if (context == NULL) {
        /* TODO: implement here. Deliver signal to user program */
        if (tcb->flags & SHIM_FLAG_SIGPENDING)
            debug("FIXME __handle_signal flags 0x%lx\n", tcb->flags);
        return;
    }

    if (context_is_internal(context) || DkInPal(context)) {
        debug("__handle_signal: in libos. just returning "
              "rip 0x%08lx +0x%08lx\n",
              context->rip,
              (void *) context->rip - (void *) &__load_address);
        return;
    }

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

        __handle_one_signal(tcb, sig, signal, context);
        free(signal);
        break;
    }
}

void handle_exit_signal(void) {
    shim_tcb_t* tcb = shim_get_tcb();
    struct shim_thread* thread = tcb->tp;
    assert(thread);
    while (atomic_read(&thread->has_signal)) {
        for (int sig = 1; sig < NUM_KNOWN_SIGS; sig++) {
            while (true) {
                struct shim_signal* signal = fetch_signal_log(thread, sig);
                if (!signal)
                    break;

                if (!__sigismember(&thread->signal_mask, sig)) {
                    __rt_sighandler_t handler;
                    restorer_t restorer;
                    get_signal_handler(thread, sig, &handler, &restorer);
                    direct_call_if_default_handler(sig, &signal->info, handler);
                }
                free(signal);
            }
        }
    }
}

void handle_sysret_signal(void) {
    shim_tcb_t* tcb = shim_get_tcb();
    struct shim_thread* thread = (struct shim_thread*)tcb->tp;

    clear_bit(SHIM_FLAG_SIGPENDING, &tcb->flags);
    /* This doesn't take user signal mask into account.
       peek_signal_log would be needed. not fetch_signal_log */
    if (atomic_read(&thread->has_signal)) {
        set_bit(SHIM_FLAG_SIGPENDING, &tcb->flags);
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
        __handle_signal(tcb, 0, NULL);

    __enable_preempt(tcb);
    debug("__enable_preempt: %s:%d\n", __FILE__, __LINE__);
}

struct sig_deliver {
    int sig;
    struct shim_signal* signal;
    __rt_sighandler_t handler;
    restorer_t restorer;
};

static bool __get_signal_to_deliver(struct sig_deliver* deliver) {
    deliver->signal = NULL;
    struct shim_thread* thread = get_cur_thread();

    while (atomic_read(&thread->has_signal)) {
        struct shim_signal* signal = NULL;
        /* signul number starts from 1 */
        int sig;
        for (sig = 1 ; sig < NUM_KNOWN_SIGS ; sig++)
            if (!__sigismember(&thread->signal_mask, sig) &&
                (signal = fetch_signal_log(thread, sig)))
                break;

        if (!signal)
            break;

        __rt_sighandler_t handler;
        restorer_t restorer;
        get_signal_handler(thread, sig, &handler, &restorer);
        if (!handler)
            continue;

        deliver->sig = sig;
        deliver->signal = signal;
        deliver->handler = handler;
        deliver->restorer = restorer;
        return true;
    }
    return false;
}


static void __setup_next_sig_frame(
    shim_tcb_t* tcb, ucontext_t* user_uc, struct sig_deliver* deliver) {
    struct sigframe* user_sigframe = (struct sigframe*)(((void*)user_uc) - 8);

    user_sigframe->restorer = deliver->restorer;
    struct shim_regs* regs = tcb->context.regs;
    regs->rsp = (unsigned long)user_sigframe;
    regs->rip = (unsigned long)deliver->handler;
    regs->rdi = (unsigned long)deliver->sig;
    regs->rsi = (unsigned long)&user_sigframe->info;
    regs->rdx = (unsigned long)&user_sigframe->uc;

    // TODO signal mask
}

/*
 * sigreturn uses this.
 * If other signal are pending still, deliver it instead of return back
 * to app. The existing sigframe can be reused.
 */
int handle_next_signal(ucontext_t* user_uc) {
    struct sig_deliver deliver;
    if (__get_signal_to_deliver(&deliver)) {
        __setup_next_sig_frame(shim_get_tcb(), user_uc, &deliver);
        free(deliver.signal);
        return 1;
    }
    return 0;
}

/*
 * 16-byte alignment on ucontext_t on signal frame
 * align struct shim_regs to 8 (mod 16) bytes
 * => align sigframe->us to 16 bytes
 */
static_assert(
    (((8 + sizeof(struct shim_regs)) + offsetof(struct sigframe, uc)) % 16) == 0,
    "signal stack frame isn't aligned to 16 byte on calling deliver_signal_on_sysret");

/*
 * host signal arrived while LibOS or PAL was running. So the emulated
 * signal was queued.
 * Now we're returning back to app.
 * setup signal frame and return from system call to signal handler.
 */
attribute_nofp uint64_t deliver_signal_on_sysret(uint64_t syscall_ret) {
    shim_tcb_t* tcb = shim_get_tcb();
    struct shim_regs* regs = tcb->context.regs;
    void* stack = (void*)regs->rsp;

    struct sig_deliver deliver;
    debug("regs: %p sp: %08lx ip: %08lx stack: %p &tcb %p tcb %p\n",
          regs, regs->rsp, regs->rip, stack, &tcb, tcb);

    clear_bit(SHIM_FLAG_SIGPENDING, &tcb->flags);
    /* FIXME: sigsuspend, sigwait, sigwaitinfo, pselect, ppoll are
     * broken because signal mask was changed when blocking and
     * is restored on returning from system call.
     * So we miss the signal which is masked in user space and
     * unmasked during blocking.
     */
    if (!__get_signal_to_deliver(&deliver)) {
        debug("no deliverable signal\n");
        return syscall_ret;
    }

    int sig = deliver.sig;
    struct shim_signal* signal = deliver.signal;
    __rt_sighandler_t handler = deliver.handler;
    restorer_t restorer = deliver.restorer;
    direct_call_if_default_handler(sig, &signal->info, handler);

    void* sp = __get_signal_stack(tcb->tp, stack);
    /*
     * FIXME:
     * For now we can't distinguish how system call is invoked
     * i.e. through calling syscalldb or jumping into syscall_wrapper.
     * If syscall is invoked as
     *   subq $RED_ZONE_SIZE, %rsp
     *   callq syscalldb
     *   addq $RED_ZONE_SIZE, %rsp
     * red zone is avoided twice unnecessarily for signal handler.
     */

    /* allocate signal frame */
    sp -= sizeof(struct sigframe) + FP_XSTATE_MAGIC2_SIZE + 64;
    sp -= fpu_xstate_size;
    sp = aligndown_sigframe(sp);
    stack = sp;
    struct sigframe* user_sigframe = stack;

    assert(&user_sigframe->uc == ALIGN_UP_PTR(&user_sigframe->uc, 16UL));
    stack += sizeof(*user_sigframe);
    stack = ALIGN_UP_PTR(stack, 64UL);
    struct _libc_fpstate* user_fpstate = stack;

    debug("regs: %p sigframe: %p uc: %p fpstate: %p\n",
          regs, user_sigframe, &user_sigframe->uc, user_fpstate);

    /* setup sigframe */
    user_sigframe->restorer = restorer;

    ucontext_t* user_uc = &user_sigframe->uc;
    user_uc->uc_flags = UC_FP_XSTATE;
    user_uc->uc_link = NULL;
    user_uc->uc_stack = tcb->tp->signal_altstack;

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
    (*gregs)[REG_RSP] = regs->rsp;
    (*gregs)[REG_RIP] = regs->rip;
    (*gregs)[REG_EFL] = regs->rflags;
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
    fpstate_save(user_fpstate);
    fpstate_reset();

    // TODO: get current sigmask and mask signal
    __sigemptyset(&user_uc->uc_sigmask);

    free(signal);

    // setup to return to signal handler
    regs->rsp = (uint64_t)user_sigframe;
    regs->rip = (unsigned long)handler;
    regs->rdi = (unsigned long)sig;
    regs->rsi = (unsigned long)&user_sigframe->info;
    regs->rdx = (unsigned long)&user_sigframe->uc;
    return /*rax=*/0;
}

// Need to hold thread->lock when calling this function
void append_signal(struct shim_thread* thread, int sig, siginfo_t* info, bool need_interrupt) {
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

static void direct_call_if_default_handler(
    int sig, siginfo_t* info, __rt_sighandler_t handler) {
    /* we know sighandler_kill only kill the thread
     * without using info and context */
    if (handler == &sighandler_kill || handler == &sighandler_core) {
        debug("direct calling sighandler_kill\n");
        // this thread exits.
        handler(sig, info, NULL);
    }
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
