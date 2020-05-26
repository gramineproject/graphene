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

#include <stdnoreturn.h>

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

void sigaction_make_defaults(struct __kernel_sigaction* sig_action) {
    sig_action->k_sa_handler = (void*)SIG_DFL;
    sig_action->sa_flags = 0;
    sig_action->sa_restorer = NULL;
    sig_action->sa_mask = 0;
}

static __rt_sighandler_t default_sighandler[NUM_SIGS];

static struct shim_signal_queue process_signal_queue = { 0 };
static uint64_t process_pending_signals = 0;

/* These checks are racy, but we can't do better anyway: signal can be delivered in any moment. */
static bool is_rt_sq_empty(struct shim_rt_signal_queue* queue) {
    return __atomic_load_n(&queue->get_idx, __ATOMIC_RELAXED)
            == __atomic_load_n(&queue->put_idx, __ATOMIC_RELAXED);
}
static bool is_standard_sq_empty(struct shim_signal** queue) {
    return !__atomic_load_n(queue, __ATOMIC_RELAXED);
}

void get_pending_signals(struct shim_thread* thread, __sigset_t* set) {
    __sigemptyset(set);

    if (__atomic_load_n(&thread->pending_signals, __ATOMIC_RELAXED) == 0
            && __atomic_load_n(&process_pending_signals, __ATOMIC_RELAXED) == 0) {
        return;
    }

    for (int sig = 1; sig < SIGRTMIN; sig++) {
        if (!is_standard_sq_empty(&thread->signal_queue.standard_signals[sig - 1])
                || !is_standard_sq_empty(&process_signal_queue.standard_signals[sig - 1])) {
            __sigaddset(set, sig);
        }
    }

    for (int sig = SIGRTMIN; sig <= NUM_SIGS; sig++) {
        if (!is_rt_sq_empty(&thread->signal_queue.rt_signal_queues[sig - SIGRTMIN])
                || !is_rt_sq_empty(&process_signal_queue.rt_signal_queues[sig - SIGRTMIN])) {
            __sigaddset(set, sig);
        }
    }
}

static bool queue_produce_standard_signal(struct shim_signal** queue, struct shim_signal* signal) {
    struct shim_signal* old;
    do {
        old = __atomic_load_n(queue, __ATOMIC_RELAXED);
        if (old) {
            return false;
        }
    } while (!__atomic_compare_exchange_n(queue, &old, signal, /*weak=*/true,
                                          __ATOMIC_RELAXED, __ATOMIC_RELAXED));
    return true;
}

/* In teory `get_idx` and `put_idx` could overflow, but adding signals with 1GHz (10**9 signals
 * per second) gives a 544 years running time before overflow, which we consider a "safe margin"
 * for now. */
static bool queue_produce_rt_signal(struct shim_rt_signal_queue* queue,
                                    struct shim_signal* signal) {
    uint64_t get_idx;
    uint64_t put_idx = __atomic_load_n(&queue->put_idx, __ATOMIC_RELAXED);
    do {
        get_idx = __atomic_load_n(&queue->get_idx, __ATOMIC_RELAXED);
        assert(put_idx >= get_idx);

        /* This is a bit racy i.e. it might report full queue, when it's just being emptied, but
         * it's the best we can do. Note that `get_idx` can only be increased, but never past
         * `put_idx`. */
        if (put_idx - get_idx >= ARRAY_SIZE(queue->queue)) {
            return false;
        }
    } while (!__atomic_compare_exchange_n(&queue->put_idx, &put_idx, put_idx + 1, /*weak=*/true,
                                          __ATOMIC_RELAXED, __ATOMIC_RELAXED));

    queue->queue[put_idx % ARRAY_SIZE(queue->queue)] = signal;
    return true;
}

static bool queue_produce_signal(struct shim_signal_queue* queue, struct shim_signal* signal) {
    int sig = signal->info.si_signo;

    if (sig < 1 || sig > NUM_SIGS) {
        return false;
    } else if (sig < SIGRTMIN) {
        return queue_produce_standard_signal(&queue->standard_signals[sig - 1], signal);
    } else {
        return queue_produce_rt_signal(&queue->rt_signal_queues[sig - SIGRTMIN], signal);
    }
}

static bool append_thread_signal(struct shim_thread* thread, struct shim_signal* signal) {
    bool ret = queue_produce_signal(&thread->signal_queue, signal);
    if (ret) {
        (void)__atomic_add_fetch(&thread->pending_signals, 1, __ATOMIC_RELAXED);
    }
    return ret;
}

static bool append_process_signal(struct shim_signal* signal) {
    bool ret = queue_produce_signal(&process_signal_queue, signal);
    if (ret) {
        (void)__atomic_add_fetch(&process_pending_signals, 1, __ATOMIC_RELAXED);
    }
    return ret;
}

static struct shim_signal* consume_standard_signal(struct shim_signal** queue) {
    return __atomic_exchange_n(queue, NULL, __ATOMIC_RELAXED);
}

static struct shim_signal* queue_consume_rt_signal(struct shim_rt_signal_queue* queue) {
    uint64_t put_idx;
    uint64_t get_idx = __atomic_load_n(&queue->get_idx, __ATOMIC_RELAXED);
    do {
        put_idx = __atomic_load_n(&queue->put_idx, __ATOMIC_RELAXED);
        assert(put_idx >= get_idx);

        if (put_idx == get_idx) {
            return NULL;
        }
    } while (!__atomic_compare_exchange_n(&queue->get_idx, &get_idx, get_idx + 1, /*weak=*/true,
                                          __ATOMIC_RELAXED, __ATOMIC_RELAXED));

    return queue->queue[get_idx % ARRAY_SIZE(queue->queue)];
}

static struct shim_signal* queue_consume_signal(struct shim_signal_queue* queue, int sig) {
    if (sig < 1 || sig > NUM_SIGS) {
        return NULL;
    } else if (sig < SIGRTMIN) {
        return consume_standard_signal(&queue->standard_signals[sig - 1]);
    } else {
        return queue_consume_rt_signal(&queue->rt_signal_queues[sig - SIGRTMIN]);
    }
}

static struct shim_signal* consume_thread_signal(struct shim_thread* thread, int sig) {
    struct shim_signal* signal = queue_consume_signal(&thread->signal_queue, sig);
    if (signal) {
        (void)__atomic_sub_fetch(&thread->pending_signals, 1, __ATOMIC_RELAXED);
    }
    return signal;
}

static struct shim_signal* consume_process_signal(int sig) {
    struct shim_signal* signal = queue_consume_signal(&process_signal_queue, sig);
    if (signal) {
        (void)__atomic_sub_fetch(&process_pending_signals, 1, __ATOMIC_RELAXED);
    }
    return signal;
}

static void __handle_one_signal(shim_tcb_t* tcb, struct shim_signal* signal);

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

    struct shim_thread* cur_thread = (struct shim_thread*)tcb->tp;
    // Signals should not be delivered before the user process starts
    // or after the user process dies.
    if (!cur_thread || !cur_thread->is_alive)
        return;

    int sig = info->si_signo;

    int64_t preempt = __disable_preempt(tcb);

    struct shim_signal * signal = __alloca(sizeof(struct shim_signal));
    /* save in signal */
    memset(signal, 0, sizeof(struct shim_signal));
    __store_info(info, signal);
    __store_context(tcb, context, signal);
    signal->pal_context = context;

    if (preempt > 1 || __sigismember(&cur_thread->signal_mask, sig)) {
        signal = malloc_copy(signal,sizeof(struct shim_signal));
        if (signal) {
            if (!append_thread_signal(cur_thread, signal)) {
                debug("signal queue is full (TID = %u, SIG = %d)\n", tcb->tid, sig);
                free(signal);
            }
        }
    } else {
        __handle_signals(tcb);
        __handle_one_signal(tcb, signal);
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

static noreturn void internal_fault(const char* errstr, PAL_NUM addr, PAL_CONTEXT* context) {
    IDTYPE tid = get_cur_tid();
    if (context_is_internal(context))
        SYS_PRINTF("%s at 0x%08lx (IP = +0x%lx, VMID = %u, TID = %u)\n", errstr,
                   addr, (void*)context->IP - (void*)&__load_address,
                   cur_process.vmid, is_internal_tid(tid) ? 0 : tid);
    else
        SYS_PRINTF("%s at 0x%08lx (IP = 0x%08lx, VMID = %u, TID = %u)\n", errstr,
                   addr, context ? context->IP : 0,
                   cur_process.vmid, is_internal_tid(tid) ? 0 : tid);

    DEBUG_BREAK_ON_FAILURE();
    DkProcessExit(1);
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
    }

    if (context)
        debug("memory fault at 0x%08lx (IP = 0x%08lx)\n", arg, context->IP);

    struct shim_vma_info vma_info;
    int signo = SIGSEGV;
    int code;
    if (!arg) {
        code = SEGV_MAPERR;
    } else if (!lookup_vma((void *) arg, &vma_info)) {
        if (vma_info.flags & VMA_INTERNAL) {
            internal_fault("Internal memory fault with VMA", arg, context);
        }
        struct shim_handle* file = vma_info.file;
        if (file && file->type == TYPE_FILE) {
            /* DEP 3/3/17: If the mapping exceeds end of a file (but is in the VMA)
             * then return a SIGBUS. */
            uintptr_t eof_in_vma = (uintptr_t)vma_info.addr + vma_info.file_offset
                                    + file->info.file.size;
            if (arg > eof_in_vma) {
                signo = SIGBUS;
                code = BUS_ADRERR;
            } else if ((context->err & 4) && !(vma_info.flags & PROT_WRITE)) {
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

        if (file) {
            put_handle(file);
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
        return !is_in_adjacent_user_vmas(addr, size);

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

            if (!access_ok(addr, maxlen) || !is_in_adjacent_user_vmas((void*) addr, maxlen))
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
    struct shim_vma_info vma_info = { .file = NULL };

    if (!is_internal_tid(get_cur_tid()) &&
        !context_is_internal(context) &&
        !(lookup_vma((void *)arg, &vma_info)) &&
        !(vma_info.flags & VMA_INTERNAL)) {

        assert(context);

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
            debug("Illegal instruction during app execution at 0x%08lx; delivering to app\n",
                  context->IP);
            deliver_signal(ALLOC_SIGINFO(SIGILL, ILL_ILLOPC,
                                         si_addr, (void *) arg), context);
        }
    } else {
        internal_fault("Illegal instruction during Graphene internal execution", arg, context);
    }

    if (vma_info.file) {
        put_handle(vma_info.file);
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
            __handle_signals(tcb);
        __enable_preempt(tcb);
    }
    DkExceptionReturn(event);
}

static void pipe_upcall(PAL_PTR event, PAL_NUM arg, PAL_CONTEXT* context) {
    if (!is_internal_tid(get_cur_tid()))
        deliver_signal(ALLOC_SIGINFO(SIGPIPE, 0, si_pid, 0), /*context=*/NULL);
    else
        internal_fault("Internal SIGPIPE fault", arg, context);
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
    DkSetExceptionHandler(&pipe_upcall,        PAL_EVENT_PIPE);
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

static __rt_sighandler_t get_sighandler(struct shim_thread* thread, int sig, bool allow_reset) {
    lock(&thread->signal_handles->lock);
    struct __kernel_sigaction* sig_action = &thread->signal_handles->actions[sig - 1];

    /*
     * on amd64, sa_handler can be treated as sa_sigaction
     * because 1-3 arguments are passed by register and
     * sa_handler simply ignores 2nd and 3rd argument.
     */
#ifndef __x86_64__
# error "get_sighandler: see the comment above"
#endif

    __rt_sighandler_t handler = (void*)sig_action->k_sa_handler;
    if (allow_reset && sig_action->sa_flags & SA_RESETHAND) {
        sigaction_make_defaults(sig_action);
    }

    if ((void*)handler == (void*)SIG_IGN) {
        handler = NULL;
    } else if ((void*)handler == (void*)SIG_DFL) {
        handler = default_sighandler[sig - 1];
    }

    unlock(&thread->signal_handles->lock);
    return handler;
}

static void
__handle_one_signal(shim_tcb_t* tcb, struct shim_signal* signal) {
    struct shim_thread* thread = (struct shim_thread*)tcb->tp;
    __rt_sighandler_t handler = NULL;

    int sig = signal->info.si_signo;

    handler = get_sighandler(thread, sig, /*allow_reset=*/true);

    if (!handler)
        return;

    debug("signal %d handled\n", sig);

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

    __atomic_store_n(&thread->signal_handled, true, __ATOMIC_RELAXED);

    if (context)
        memcpy(&tcb->context, context, sizeof(struct shim_context));

    if (signal->pal_context)
        memcpy(signal->pal_context, signal->context.uc_mcontext.gregs, sizeof(PAL_CONTEXT));
}

void __handle_signals(shim_tcb_t* tcb) {
    struct shim_thread* thread = tcb->tp;
    assert(thread);

    if (is_internal(thread)) {
        return;
    }

    if (thread->time_to_die) {
        thread_exit(0, 0);
    }

    while (__atomic_load_n(&thread->pending_signals, __ATOMIC_RELAXED)
           || __atomic_load_n(&process_pending_signals, __ATOMIC_RELAXED)) {
        struct shim_signal* signal = NULL;

        for (int sig = 1; sig <= NUM_SIGS; sig++) {
            if (!__sigismember(&thread->signal_mask, sig)) {
                if ((signal = consume_thread_signal(thread, sig))) {
                    break;
                }
                if ((signal = consume_process_signal(sig))) {
                    break;
                }
            }
        }

        if (!signal) {
            break;
        }

        if (!signal->context_stored) {
            __store_context(tcb, NULL, signal);
        }

        __handle_one_signal(tcb, signal);
        free(signal);
    }
}

void handle_signals(void) {
    shim_tcb_t * tcb = shim_get_tcb();
    assert(tcb);

    int64_t preempt = __disable_preempt(tcb);

    if (preempt > 1)
        debug("signal delayed (%ld)\n", preempt);
    else
        __handle_signals(tcb);

    __enable_preempt(tcb);
}

bool append_signal(struct shim_thread* thread, siginfo_t* info) {
    assert(!thread || locked(&thread->lock));
    assert(info);

    // TODO: ignore SIGCHLD even if it's masked, when handler is set to SIG_IGN (probably not here)

    struct shim_signal* signal = malloc(sizeof(*signal));
    if (!signal) {
        return false;
    }

    /* save in signal */
    __store_info(info, signal);
    signal->context_stored = false;

    if (thread) {
        if (append_thread_signal(thread, signal)) {
            return true;
        }
    } else {
        if (append_process_signal(signal)) {
            return true;
        }
    }

    debug("signal queue is full (TID = %u%s, SIG = %d)\n",
          thread ? thread->tid : 0, thread ? "" : "(process)",
          info->si_signo);
    free(signal);
    /* This is counter-intuitive, but we report success here: after all signal was successfully
     * delivered, just the queue was full. */
    return true;
}

#define __WCOREDUMP_BIT 0x80

static void sighandler_kill(int sig, siginfo_t* info, void* ucontext) {
    __UNUSED(info);
    __UNUSED(ucontext);
    debug("killed by signal %d\n", sig & ~__WCOREDUMP_BIT);

    process_exit(0, sig);
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

BEGIN_CP_FUNC(pending_signals)
{
    __UNUSED(obj);
    __UNUSED(size);
    __UNUSED(objp);

    /* This is a bit racy, but we cannot do any better. If a app spams itself with signals while
     * doing execve, some pending signals might not get checkpointed. /me shrugs */
    uint64_t n = __atomic_load_n(&process_pending_signals, __ATOMIC_RELAXED);
    uint64_t i = 0;
    assert(n <= SIGRTMIN - 1 + (NUM_SIGS - SIGRTMIN + 1) * MAX_SIGNAL_LOG);
    siginfo_t infos[n];
    memset(&infos, 0, sizeof(infos));

    for (int sig = 1; sig < SIGRTMIN && i < n; sig++) {
        struct shim_signal** q = &process_signal_queue.standard_signals[sig - 1];
        struct shim_signal* signal = __atomic_load_n(q, __ATOMIC_RELAXED);
        if (signal) {
            memcpy(&infos[i], &signal->info, sizeof(infos[i]));
            i++;
        }
    }

    for (int sig = SIGRTMIN; sig <= NUM_SIGS && i < n; sig++) {
        struct shim_rt_signal_queue* q = &process_signal_queue.rt_signal_queues[sig - SIGRTMIN];
        uint64_t idx = __atomic_load_n(&q->put_idx, __ATOMIC_RELAXED);
        while (__atomic_load_n(&q->get_idx, __ATOMIC_RELAXED) < idx && i < n) {
            memcpy(&infos[i], &q->queue[(idx - 1) % ARRAY_SIZE(q->queue)]->info, sizeof(infos[i]));
            idx--;
            i++;
        }
    }

    size_t off = ADD_CP_OFFSET(sizeof(i) + sizeof(infos[0]) * i);
    memcpy((char*)base + off, &i, sizeof(i));
    memcpy((char*)base + off + sizeof(i), &infos, sizeof(infos[0]) * i);
    ADD_CP_FUNC_ENTRY(off);
}
END_CP_FUNC(pending_signals)

BEGIN_RS_FUNC(pending_signals)
{
    __UNUSED(offset);
    __UNUSED(rebase);

    size_t off = GET_CP_FUNC_ENTRY();
    size_t n = *(size_t*)((char*)base + off);
    siginfo_t* infos = (siginfo_t*)((char*)base + off + sizeof(n));
    for (size_t i = 0; i < n; i++) {
        struct shim_signal* signal = malloc(sizeof(*signal));
        if (!signal) {
            return -ENOMEM;
        }
        if (!infos[i].si_signo) {
            continue;
        }
        memcpy(&signal->info, &infos[i], sizeof(signal->info));
        signal->context_stored = false;
        signal->pal_context = NULL;
        if (!append_process_signal(signal)) {
            return -EAGAIN;
        }
    }
}
END_RS_FUNC(pending_signals)
