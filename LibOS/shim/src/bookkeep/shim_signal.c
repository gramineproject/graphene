/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

/*
 * This file contains code for handling signals and exceptions passed from PAL.
 */

#include <stddef.h> /* linux/signal.h misses this dependency (for size_t), at least on Ubuntu 16.04.
                     * We must include it ourselves before including linux/signal.h.
                     */

#include <asm/signal.h>
#include <stdnoreturn.h>

#include "cpu.h"
#include "pal.h"
#include "shim_checkpoint.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_lock.h"
#include "shim_process.h"
#include "shim_signal.h"
#include "shim_table.h"
#include "shim_thread.h"
#include "shim_types.h"
#include "shim_ucontext-arch.h"
#include "shim_utils.h"
#include "shim_vma.h"

// __rt_sighandler_t is different from __sighandler_t in <asm-generic/signal-defs.h>:
//    typedef void __signalfn_t(int);
//    typedef __signalfn_t *__sighandler_t

typedef void (*__rt_sighandler_t)(int, siginfo_t*, void*);

void sigaction_make_defaults(struct __kernel_sigaction* sig_action) {
    sig_action->k_sa_handler = (void*)SIG_DFL;
    sig_action->sa_flags     = 0;
    sig_action->sa_restorer  = NULL;
    __sigemptyset(&sig_action->sa_mask);
}

void thread_sigaction_reset_on_execve(struct shim_thread* thread) {
    lock(&thread->signal_dispositions->lock);
    for (size_t i = 0; i < ARRAY_SIZE(thread->signal_dispositions->actions); i++) {
        struct __kernel_sigaction* sig_action = &thread->signal_dispositions->actions[i];

        __sighandler_t handler = sig_action->k_sa_handler;
        if (handler == (void*)SIG_DFL || handler == (void*)SIG_IGN) {
            /* POSIX.1: dispositions of any signals that are ignored or set to the default are left
             * unchanged. On Linux, this rule applies to SIGCHLD as well. */
            continue;
        }

        /* app installed its own signal handler, reset it to default */
        sigaction_make_defaults(sig_action);
    }
    unlock(&thread->signal_dispositions->lock);
}

static __rt_sighandler_t default_sighandler[NUM_SIGS];

static struct shim_signal_queue process_signal_queue = {0};
/* This is just an optimization, not to have to check the queue for pending signals. A thread will
 * be woken up after signal is appended to its queue and will handle all unblocked pending signals
 * no matter what is the relative ordering of increasing this variable vs. appending signal to
 * the queue. */
static uint64_t process_pending_signals_cnt = 0;

/*
 * These checks are racy, but we can't do better anyway: signal can be delivered in any moment.
 * Worst case scenario we report a real-time signal queue being empty just when a signal is being
 * appended.
 *
 * TODO: we need to consider removing the ability of outside world to deliver signals to a app
 * running inside Graphene (this might be important on Linux-SGX PAL). In such case it would be
 * probably impossible for an app to be preempted while appending a signal and needing to append
 * another one. This would allow for using proper locking scheme here.
 */
static bool is_rt_sq_empty(struct shim_rt_signal_queue* queue) {
    return __atomic_load_n(&queue->get_idx, __ATOMIC_ACQUIRE)
           == __atomic_load_n(&queue->put_idx, __ATOMIC_ACQUIRE);
}

static bool has_standard_signal(struct shim_signal** queue) {
    return !!__atomic_load_n(queue, __ATOMIC_ACQUIRE);
}

void get_pending_signals(struct shim_thread* thread, __sigset_t* set) {
    __sigemptyset(set);

    if (__atomic_load_n(&thread->pending_signals, __ATOMIC_ACQUIRE) == 0
            && __atomic_load_n(&process_pending_signals_cnt, __ATOMIC_ACQUIRE) == 0) {
        return;
    }

    for (int sig = 1; sig < SIGRTMIN; sig++) {
        if (has_standard_signal(&thread->signal_queue.standard_signals[sig - 1])
                || has_standard_signal(&process_signal_queue.standard_signals[sig - 1])) {
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

static bool append_standard_signal(struct shim_signal** signal_slot, struct shim_signal* signal) {
    struct shim_signal* old = NULL;
    return __atomic_compare_exchange_n(signal_slot, &old, signal, /*weak=*/false, __ATOMIC_RELEASE,
                                       __ATOMIC_ACQUIRE);
}

/* In theory `get_idx` and `put_idx` could overflow, but adding signals with 1GHz (10**9 signals
 * per second) gives a 544 years running time before overflow, which we consider a "safe margin"
 * for now. */
static bool append_rt_signal(struct shim_rt_signal_queue* queue, struct shim_signal* signal) {
    uint64_t get_idx;
    uint64_t put_idx = __atomic_load_n(&queue->put_idx, __ATOMIC_ACQUIRE);
    do {
        get_idx = __atomic_load_n(&queue->get_idx, __ATOMIC_ACQUIRE);
        assert(put_idx >= get_idx);

        /* This is a bit racy i.e. it might report full queue, when it's just being emptied, but
         * it's the best we can do. Note that `get_idx` can only be increased, but never past
         * `put_idx`. */
        if (put_idx - get_idx >= ARRAY_SIZE(queue->queue)) {
            return false;
        }
    } while (!__atomic_compare_exchange_n(&queue->put_idx, &put_idx, put_idx + 1, /*weak=*/false,
                                          __ATOMIC_RELEASE, __ATOMIC_ACQUIRE));

    queue->queue[put_idx % ARRAY_SIZE(queue->queue)] = signal;
    return true;
}

static bool queue_append_signal(struct shim_signal_queue* queue, struct shim_signal* signal) {
    int sig = signal->info.si_signo;

    if (sig < 1 || sig > NUM_SIGS) {
        return false;
    } else if (sig < SIGRTMIN) {
        return append_standard_signal(&queue->standard_signals[sig - 1], signal);
    } else {
        return append_rt_signal(&queue->rt_signal_queues[sig - SIGRTMIN], signal);
    }
}

static bool append_thread_signal(struct shim_thread* thread, struct shim_signal* signal) {
    bool ret = queue_append_signal(&thread->signal_queue, signal);
    if (ret) {
        (void)__atomic_add_fetch(&thread->pending_signals, 1, __ATOMIC_RELEASE);
    }
    return ret;
}

static bool append_process_signal(struct shim_signal* signal) {
    bool ret = queue_append_signal(&process_signal_queue, signal);
    if (ret) {
        (void)__atomic_add_fetch(&process_pending_signals_cnt, 1, __ATOMIC_RELEASE);
    }
    return ret;
}

static struct shim_signal* pop_standard_signal(struct shim_signal** signal_slot) {
    return __atomic_exchange_n(signal_slot, NULL, __ATOMIC_ACQ_REL);
}

static struct shim_signal* pop_rt_signal(struct shim_rt_signal_queue* queue) {
    uint64_t put_idx;
    uint64_t get_idx = __atomic_load_n(&queue->get_idx, __ATOMIC_ACQUIRE);
    do {
        put_idx = __atomic_load_n(&queue->put_idx, __ATOMIC_ACQUIRE);
        assert(put_idx >= get_idx);

        if (put_idx == get_idx) {
            return NULL;
        }
    } while (!__atomic_compare_exchange_n(&queue->get_idx, &get_idx, get_idx + 1, /*weak=*/false,
                                          __ATOMIC_RELEASE, __ATOMIC_ACQUIRE));

    return queue->queue[get_idx % ARRAY_SIZE(queue->queue)];
}

static struct shim_signal* queue_pop_signal(struct shim_signal_queue* queue, int sig) {
    if (sig < 1 || sig > NUM_SIGS) {
        return NULL;
    } else if (sig < SIGRTMIN) {
        return pop_standard_signal(&queue->standard_signals[sig - 1]);
    } else {
        return pop_rt_signal(&queue->rt_signal_queues[sig - SIGRTMIN]);
    }
}

static struct shim_signal* thread_pop_signal(struct shim_thread* thread, int sig) {
    struct shim_signal* signal = queue_pop_signal(&thread->signal_queue, sig);
    if (signal) {
        (void)__atomic_sub_fetch(&thread->pending_signals, 1, __ATOMIC_ACQUIRE);
    }
    return signal;
}

static struct shim_signal* process_pop_signal(int sig) {
    struct shim_signal* signal = queue_pop_signal(&process_signal_queue, sig);
    if (signal) {
        (void)__atomic_sub_fetch(&process_pending_signals_cnt, 1, __ATOMIC_ACQUIRE);
    }
    return signal;
}

void clear_signal_queue(struct shim_signal_queue* queue) {
    for (int sig = 1; sig <= NUM_SIGS; sig++) {
        struct shim_signal* signal;
        while ((signal = queue_pop_signal(queue, sig))) {
            free(signal);
        }
    }
}

static void __handle_one_signal(shim_tcb_t* tcb, struct shim_signal* signal);

static void __store_info(siginfo_t* info, struct shim_signal* signal) {
    if (info)
        signal->info = *info;
}

void __store_context(shim_tcb_t* tcb, PAL_CONTEXT* pal_context, struct shim_signal* signal) {
    ucontext_t* context = &signal->context;

    if (tcb && tcb->context.regs && shim_context_get_syscallnr(&tcb->context)) {
        struct shim_context* ct = &tcb->context;

        if (ct->regs)
            shim_regs_to_ucontext(context, ct->regs);

        signal->context_stored = true;
        return;
    }

    if (pal_context) {
        pal_context_to_ucontext(context, pal_context);
        signal->context_stored = true;
    }
}

void deliver_signal(siginfo_t* info, PAL_CONTEXT* context) {
    shim_tcb_t* tcb = shim_get_tcb();
    assert(tcb);

    struct shim_thread* cur_thread = (struct shim_thread*)tcb->tp;
    assert(cur_thread);

    int sig = info->si_signo;

    int64_t preempt = __disable_preempt(tcb);

    struct shim_signal* signal = __alloca(sizeof(struct shim_signal));
    /* save in signal */
    memset(signal, 0, sizeof(struct shim_signal));
    __store_info(info, signal);
    __store_context(tcb, context, signal);
    signal->pal_context = context;

    if (preempt > 1 || __sigismember(&cur_thread->signal_mask, sig)) {
        signal = malloc_copy(signal, sizeof(struct shim_signal));
        if (signal) {
            if (!append_thread_signal(cur_thread, signal)) {
                debug("Signal %d queue of thread %u is full, dropping the incoming signal\n", sig,
                      cur_thread->tid);
                free(signal);
            }
        }
    } else {
        __handle_one_signal(tcb, signal);
        __handle_signals(tcb);
    }

    __enable_preempt(tcb);
}

#define ALLOC_SIGINFO(signo, code, member, value)       \
    ({                                                  \
        siginfo_t* _info = __alloca(sizeof(siginfo_t)); \
        memset(_info, 0, sizeof(siginfo_t));            \
        _info->si_signo = (signo);                      \
        _info->si_code  = (code);                       \
        _info->member   = (value);                      \
        _info;                                          \
    })

static inline bool context_is_internal(PAL_CONTEXT* context) {
    if (!context)
        return false;

    void* ip = (void*)pal_context_get_ip(context);

    return (void*)&__code_address <= ip && ip < (void*)&__code_address_end;
}

static noreturn void internal_fault(const char* errstr, PAL_NUM addr, PAL_CONTEXT* context) {
    IDTYPE tid = get_cur_tid();
    PAL_NUM ip = pal_context_get_ip(context);

    if (context_is_internal(context))
        warn("%s at 0x%08lx (IP = +0x%lx, VMID = %u, TID = %u)\n", errstr, addr,
             (void*)ip - (void*)&__load_address, g_process_ipc_info.vmid,
             is_internal_tid(tid) ? 0 : tid);
    else
        warn("%s at 0x%08lx (IP = 0x%08lx, VMID = %u, TID = %u)\n", errstr, addr,
             context ? ip : 0, g_process_ipc_info.vmid, is_internal_tid(tid) ? 0 : tid);

    DEBUG_BREAK_ON_FAILURE();
    DkProcessExit(1);
}

static void arithmetic_error_upcall(PAL_NUM arg, PAL_CONTEXT* context) {
    if (is_internal_tid(get_cur_tid()) || context_is_internal(context)) {
        internal_fault("Internal arithmetic fault", arg, context);
    } else {
        if (context)
            debug("arithmetic fault at 0x%08lx\n", pal_context_get_ip(context));

        deliver_signal(ALLOC_SIGINFO(SIGFPE, FPE_INTDIV, si_addr, (void*)arg), context);
    }
}

static void memfault_upcall(PAL_NUM arg, PAL_CONTEXT* context) {
    shim_tcb_t* tcb = shim_get_tcb();
    assert(tcb);

    if (tcb->test_range.cont_addr && (void*)arg >= tcb->test_range.start &&
            (void*)arg <= tcb->test_range.end) {
        assert(context);
        tcb->test_range.has_fault = true;
        pal_context_set_ip(context, (PAL_NUM)tcb->test_range.cont_addr);
        return;
    }

    if (is_internal_tid(get_cur_tid()) || context_is_internal(context)) {
        internal_fault("Internal memory fault", arg, context);
    }

    if (context)
        debug("memory fault at 0x%08lx (IP = 0x%08lx)\n", arg, pal_context_get_ip(context));

    struct shim_vma_info vma_info;
    int signo = SIGSEGV;
    int code;
    if (!arg) {
        code = SEGV_MAPERR;
    } else if (!lookup_vma((void*)arg, &vma_info)) {
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
            } else if (pal_context_has_user_pagefault(context) && !(vma_info.flags & PROT_WRITE)) {
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

    deliver_signal(ALLOC_SIGINFO(signo, code, si_addr, (void*)arg), context);
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
    static struct atomic_int sgx_pal = {.counter = 0};
    static struct atomic_int inited  = {.counter = 0};

    if (!__atomic_load_n(&inited.counter, __ATOMIC_SEQ_CST)) {
        /* Ensure that is_sgx_pal is updated before initialized */
        __atomic_store_n(&sgx_pal.counter, !strcmp(PAL_CB(host_type), "Linux-SGX"),
                         __ATOMIC_SEQ_CST);
        __atomic_store_n(&inited.counter, 1, __ATOMIC_SEQ_CST);
    }

    return __atomic_load_n(&sgx_pal.counter, __ATOMIC_SEQ_CST) != 0;
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
bool test_user_memory(void* addr, size_t size, bool write) {
    if (!size)
        return false;

    if (!access_ok(addr, size))
        return true;

    /* SGX path: check if [addr, addr+size) is addressable (in some VMA) */
    if (is_sgx_pal())
        return !is_in_adjacent_user_vmas(addr, size);

    /* Non-SGX path: check if [addr, addr+size) is addressable by touching
     * a byte of each page; invalid access will be caught in memfault_upcall */
    shim_tcb_t* tcb = shim_get_tcb();
    assert(tcb && tcb->tp);
    __disable_preempt(tcb);

    /* Add the memory region to the watch list. This is not racy because
     * each thread has its own record. */
    assert(!tcb->test_range.cont_addr);
    tcb->test_range.has_fault = false;
    tcb->test_range.cont_addr = &&ret_fault;
    tcb->test_range.start     = addr;
    tcb->test_range.end       = addr + size - 1;
    /* enforce compiler to store tcb->test_range into memory */
    COMPILER_BARRIER();

    /* Try to read or write into one byte inside each page */
    void* tmp = addr;
    while (tmp <= addr + size - 1) {
        if (write) {
            *(volatile char*)tmp = *(volatile char*)tmp;
        } else {
            *(volatile char*)tmp;
        }
        tmp = ALLOC_ALIGN_UP_PTR(tmp + 1);
    }

ret_fault:
    /* enforce compiler to load tcb->test_range.has_fault below */
    COMPILER_BARRIER();

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
bool test_user_string(const char* addr) {
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

            if (!access_ok(addr, maxlen) || !is_in_adjacent_user_vmas((void*)addr, maxlen))
                return true;

            size = strnlen(addr, maxlen);
            addr = next;
            next = ALLOC_ALIGN_UP_PTR(addr + 1);
        } while (size == maxlen);

        return false;
    }

    /* Non-SGX path: check if [addr, addr+size) is addressable by touching
     * a byte of each page; invalid access will be caught in memfault_upcall. */
    shim_tcb_t* tcb = shim_get_tcb();
    assert(tcb && tcb->tp);
    __disable_preempt(tcb);

    assert(!tcb->test_range.cont_addr);
    tcb->test_range.has_fault = false;
    tcb->test_range.cont_addr = &&ret_fault;
    /* enforce compiler to store tcb->test_range into memory */
    COMPILER_BARRIER();

    do {
        /* Add the memory region to the watch list. This is not racy because
         * each thread has its own record. */
        tcb->test_range.start = (void*)addr;
        tcb->test_range.end   = (void*)(next - 1);

        maxlen = next - addr;

        if (!access_ok(addr, maxlen))
            return true;
        *(volatile char*)addr; /* try to read one byte from the page */

        size = strnlen(addr, maxlen);
        addr = next;
        next = ALLOC_ALIGN_UP_PTR(addr + 1);
    } while (size == maxlen);

ret_fault:
    /* enforce compiler to load tcb->test_range.has_fault below */
    COMPILER_BARRIER();

    /* If any read or write into the target region causes an exception,
     * the control flow will immediately jump to here. */
    bool has_fault = tcb->test_range.has_fault;
    tcb->test_range.has_fault = false;
    tcb->test_range.cont_addr = NULL;
    tcb->test_range.start = tcb->test_range.end = NULL;
    __enable_preempt(tcb);
    return has_fault;
}

static void illegal_upcall(PAL_NUM arg, PAL_CONTEXT* context) {
    struct shim_vma_info vma_info = {.file = NULL};

    if (!is_internal_tid(get_cur_tid()) && !context_is_internal(context) &&
            !(lookup_vma((void*)arg, &vma_info)) && !(vma_info.flags & VMA_INTERNAL)) {
        assert(context);

        uint8_t* rip = (uint8_t*)pal_context_get_ip(context);
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
                  (unsigned long)rip);
            deliver_signal(ALLOC_SIGINFO(SIGILL, ILL_ILLOPC, si_addr, (void*)arg), context);
        }
    } else {
        internal_fault("Illegal instruction during Graphene internal execution", arg, context);
    }

    if (vma_info.file) {
        put_handle(vma_info.file);
    }
}

static void quit_upcall(PAL_NUM arg, PAL_CONTEXT* context) {
    __UNUSED(arg);
    __UNUSED(context);
    siginfo_t info = {
        .si_signo = SIGTERM,
        .si_pid = 0,
        .si_code = SI_USER,
    };
    if (kill_current_proc(&info) < 0) {
        debug("quit_upcall: failed to deliver a signal\n");
    }
}

static void suspend_upcall(PAL_NUM arg, PAL_CONTEXT* context) {
    __UNUSED(arg);
    __UNUSED(context);
    siginfo_t info = {
        .si_signo = SIGINT,
        .si_pid = 0,
        .si_code = SI_USER,
    };
    if (kill_current_proc(&info) < 0) {
        debug("suspend_upcall: failed to deliver a signal\n");
    }
}

static void resume_upcall(PAL_NUM arg, PAL_CONTEXT* context) {
    __UNUSED(arg);
    __UNUSED(context);
    shim_tcb_t* tcb = shim_get_tcb();
    if (!tcb || !tcb->tp)
        return;

    if (!is_internal_tid(get_cur_tid())) {
        int64_t preempt = __disable_preempt(tcb);
        if (preempt <= 1)
            __handle_signals(tcb);
        __enable_preempt(tcb);
    }
}

int init_signal(void) {
    DkSetExceptionHandler(&arithmetic_error_upcall, PAL_EVENT_ARITHMETIC_ERROR);
    DkSetExceptionHandler(&memfault_upcall,         PAL_EVENT_MEMFAULT);
    DkSetExceptionHandler(&illegal_upcall,          PAL_EVENT_ILLEGAL);
    DkSetExceptionHandler(&quit_upcall,             PAL_EVENT_QUIT);
    DkSetExceptionHandler(&suspend_upcall,          PAL_EVENT_SUSPEND);
    DkSetExceptionHandler(&resume_upcall,           PAL_EVENT_RESUME);
    return 0;
}

void clear_illegal_signals(__sigset_t* set) {
    __sigdelset(set, SIGKILL);
    __sigdelset(set, SIGSTOP);
}

void get_sig_mask(struct shim_thread* thread, __sigset_t* mask) {
    assert(thread);

    *mask = thread->signal_mask;
}

void set_sig_mask(struct shim_thread* thread, const __sigset_t* set) {
    assert(thread);
    assert(set);
    assert(locked(&thread->lock));

    thread->signal_mask = *set;
}

static void get_sighandler(struct shim_thread* thread, int sig, bool allow_reset,
                           __rt_sighandler_t* handler_ptr, unsigned long* sa_flags_ptr) {
    lock(&thread->signal_dispositions->lock);
    struct __kernel_sigaction* sig_action = &thread->signal_dispositions->actions[sig - 1];

    /*
     * on amd64, sa_handler can be treated as sa_sigaction
     * because 1-3 arguments are passed by register and
     * sa_handler simply ignores 2nd and 3rd argument.
     */
#ifndef __x86_64__
#error "get_sighandler: see the comment above"
#endif

    __rt_sighandler_t handler = (void*)sig_action->k_sa_handler;
    if ((void*)handler == (void*)SIG_IGN) {
        handler = NULL;
    } else if ((void*)handler == (void*)SIG_DFL) {
        handler = default_sighandler[sig - 1];
    }

    unsigned long sa_flags = sig_action->sa_flags;

    if (allow_reset && handler && sa_flags & SA_RESETHAND) {
        sigaction_make_defaults(sig_action);
    }

    unlock(&thread->signal_dispositions->lock);

    *handler_ptr = handler;
    *sa_flags_ptr = sa_flags;
}

static void __handle_one_signal(shim_tcb_t* tcb, struct shim_signal* signal) {
    struct shim_thread* thread = (struct shim_thread*)tcb->tp;
    __rt_sighandler_t handler = NULL;
    unsigned long sa_flags = 0;

    int sig = signal->info.si_signo;

    get_sighandler(thread, sig, /*allow_reset=*/true, &handler, &sa_flags);

    if (!handler)
        return;

    debug("signal %d handled\n", sig);

    // If the context is never stored in the signal, it means the signal is handled during
    // system calls, and before the thread is resumed.
    if (!signal->context_stored)
        __store_context(tcb, NULL, signal);

    struct shim_context* context = NULL;

    if (tcb->context.regs && shim_context_get_syscallnr(&tcb->context)) {
        context = __alloca(sizeof(struct shim_context));
        *context = tcb->context;
        shim_context_set_syscallnr(&tcb->context, 0);
    }

    debug("run signal handler %p (%d, %p, %p)\n", handler, sig, &signal->info, &signal->context);

    (*handler)(sig, &signal->info, &signal->context);

    if (sa_flags & SA_RESTART) {
        unsigned char signal_handled = __atomic_load_n(&thread->signal_handled, __ATOMIC_ACQUIRE);
        /* Do not overwrite `SIGNAL_HANDLED`, as we want to keep information about signals that do
         * not cause syscall restarts. */
        while (signal_handled != SIGNAL_HANDLED) {
            if (__atomic_compare_exchange_n(&thread->signal_handled, &signal_handled,
                                            SIGNAL_HANDLED_RESTART, /*weak=*/true,
                                            __ATOMIC_RELEASE, __ATOMIC_ACQUIRE)) {
                break;
            }
        }
    } else {
        __atomic_store_n(&thread->signal_handled, SIGNAL_HANDLED, __ATOMIC_RELEASE);
    }

    if (context)
        tcb->context = *context;

    if (signal->pal_context)
        ucontext_to_pal_context(signal->pal_context, &signal->context);
}

void __handle_signals(shim_tcb_t* tcb) {
    struct shim_thread* thread = tcb->tp;
    assert(thread);

    if (is_internal(thread)) {
        return;
    }

    if (thread->time_to_die) {
        thread_exit(/*error_code=*/0, /*term_signal=*/0);
    }

    while (__atomic_load_n(&thread->pending_signals, __ATOMIC_ACQUIRE)
           || __atomic_load_n(&process_pending_signals_cnt, __ATOMIC_ACQUIRE)) {
        struct shim_signal* signal = NULL;

        for (int sig = 1; sig <= NUM_SIGS; sig++) {
            if (!__sigismember(&thread->signal_mask, sig)) {
                if ((signal = thread_pop_signal(thread, sig))) {
                    break;
                }
                if ((signal = process_pop_signal(sig))) {
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
    shim_tcb_t* tcb = shim_get_tcb();
    assert(tcb);

    int64_t preempt_level = __disable_preempt(tcb);
    if (preempt_level == 1) {
        /* upon entering this function, preempt level was 0 and thus we can handle signals now
         * (otherwise preempt level was 1+, indicating that we are in signal handler; we don't
         * support nested sighandling so we defer such signals until preempt level is 0 again) */
        __handle_signals(tcb);
    }
    __enable_preempt(tcb);
}

int append_signal(struct shim_thread* thread, siginfo_t* info) {
    assert(info);

    // TODO: ignore SIGCHLD even if it's masked, when handler is set to SIG_IGN (probably not here)

    struct shim_signal* signal = malloc(sizeof(*signal));
    if (!signal) {
        return -ENOMEM;
    }

    /* save in signal */
    __store_info(info, signal);
    signal->context_stored = false;
    signal->pal_context    = NULL;

    if (thread) {
        if (append_thread_signal(thread, signal)) {
            return 0;
        }
    } else {
        if (append_process_signal(signal)) {
            return 0;
        }
    }

    debug("Signal %d queue of ", info->si_signo);
    if (thread) {
        debug("thread %u", thread->tid);
    } else {
        debug("process");
    }
    debug(" is full, dropping the incoming signal\n");
    free(signal);
    /* This is counter-intuitive, but we report success here: after all signal was successfully
     * delivered, just the queue was full. */
    return 0;
}

static void sighandler_kill(int sig, siginfo_t* info, void* ucontext) {
    __UNUSED(info);
    __UNUSED(ucontext);
    debug("killed by signal %d\n", sig & ~__WCOREDUMP_BIT);

    process_exit(0, sig);
}

static void sighandler_core(int sig, siginfo_t* info, void* ucontext) {
    /* NOTE: This implementation only indicates the core dump for wait4()
     *       and friends. No actual core-dump file is created. */
    sig = __WCOREDUMP_BIT | sig;
    sighandler_kill(sig, info, ucontext);
}

static __rt_sighandler_t default_sighandler[NUM_SIGS] = {
        [SIGHUP    - 1] = &sighandler_kill,
        [SIGINT    - 1] = &sighandler_kill,
        [SIGQUIT   - 1] = &sighandler_core,
        [SIGILL    - 1] = &sighandler_core,
        [SIGTRAP   - 1] = &sighandler_core,
        [SIGABRT   - 1] = &sighandler_core,
        [SIGBUS    - 1] = &sighandler_core,
        [SIGFPE    - 1] = &sighandler_core,
        [SIGKILL   - 1] = &sighandler_kill,
        [SIGUSR1   - 1] = &sighandler_kill,
        [SIGSEGV   - 1] = &sighandler_core,
        [SIGUSR2   - 1] = &sighandler_kill,
        [SIGPIPE   - 1] = &sighandler_kill,
        [SIGALRM   - 1] = &sighandler_kill,
        [SIGTERM   - 1] = &sighandler_kill,
        [SIGSTKFLT - 1] = &sighandler_kill,
        [SIGCHLD   - 1] = NULL,
        [SIGCONT   - 1] = NULL,
        [SIGSTOP   - 1] = NULL,
        [SIGTSTP   - 1] = NULL,
        [SIGTTIN   - 1] = NULL,
        [SIGTTOU   - 1] = NULL,
        [SIGURG    - 1] = NULL,
        [SIGXCPU   - 1] = &sighandler_core,
        [SIGXFSZ   - 1] = &sighandler_core,
        [SIGVTALRM - 1] = &sighandler_kill,
        [SIGPROF   - 1] = &sighandler_kill,
        [SIGWINCH  - 1] = NULL,
        [SIGIO     - 1] = &sighandler_kill,
        [SIGPWR    - 1] = &sighandler_kill,
        [SIGSYS    - 1] = &sighandler_core,
    };

BEGIN_CP_FUNC(pending_signals) {
    __UNUSED(obj);
    __UNUSED(size);
    __UNUSED(objp);

    /* This is a bit racy, but we cannot do any better. If an app gets spammed with signals while
     * doing execve, some pending signals might not get checkpointed; we add an arbitrary number of
     * safe margin slots. */
    const size_t SAFE_MARGIN_SLOTS = 10;
    uint64_t n = __atomic_load_n(&process_pending_signals_cnt, __ATOMIC_ACQUIRE)
                 + SAFE_MARGIN_SLOTS;
    uint64_t i = 0;
    assert(n <= SIGRTMIN - 1 + (NUM_SIGS - SIGRTMIN + 1) * MAX_SIGNAL_LOG + SAFE_MARGIN_SLOTS);
    siginfo_t infos[n];
    memset(&infos, 0, sizeof(infos));

    for (int sig = 1; sig < SIGRTMIN && i < n; sig++) {
        struct shim_signal** q = &process_signal_queue.standard_signals[sig - 1];
        /* This load might look racy, but the only scenario that this signal is removed from
         * the queue is another thread handling it. We are doing an execve, so we are the only
         * thread existing. */
        struct shim_signal* signal = __atomic_load_n(q, __ATOMIC_ACQUIRE);
        if (signal) {
            infos[i] = signal->info;
            i++;
        }
    }

    for (int sig = SIGRTMIN; sig <= NUM_SIGS && i < n; sig++) {
        struct shim_rt_signal_queue* q = &process_signal_queue.rt_signal_queues[sig - SIGRTMIN];
        uint64_t idx = __atomic_load_n(&q->put_idx, __ATOMIC_ACQUIRE);
        while (__atomic_load_n(&q->get_idx, __ATOMIC_ACQUIRE) < idx && i < n) {
            infos[i] = q->queue[(idx - 1) % ARRAY_SIZE(q->queue)]->info;
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

BEGIN_RS_FUNC(pending_signals) {
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

        assert(infos[i].si_signo);

        signal->info = infos[i];
        signal->context_stored = false;
        signal->pal_context    = NULL;
        if (!append_process_signal(signal)) {
            return -EAGAIN;
        }
    }
}
END_RS_FUNC(pending_signals)
