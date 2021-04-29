/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

/*
 * This file contains code for handling signals and exceptions passed from PAL.
 */

#include <stddef.h> /* needed by <linux/signal.h> for size_t */

#include <asm/signal.h>
#include <stdnoreturn.h>

#include "cpu.h"
#include "pal.h"
#include "shim_checkpoint.h"
#include "shim_entry.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_lock.h"
#include "shim_process.h"
#include "shim_signal.h"
#include "shim_table.h"
#include "shim_thread.h"
#include "shim_types.h"
#include "shim_utils.h"
#include "shim_vma.h"
#include "toml.h"

static bool g_check_invalid_ptrs = true;

void sigaction_make_defaults(struct __kernel_sigaction* sig_action) {
    sig_action->k_sa_handler = (void*)SIG_DFL;
    sig_action->sa_flags     = 0;
    sig_action->sa_restorer  = NULL;
    __sigemptyset(&sig_action->sa_mask);
}

void thread_sigaction_reset_on_execve(void) {
    struct shim_thread* current = get_cur_thread();

    lock(&current->signal_dispositions->lock);
    for (size_t i = 0; i < ARRAY_SIZE(current->signal_dispositions->actions); i++) {
        struct __kernel_sigaction* sig_action = &current->signal_dispositions->actions[i];

        __sighandler_t handler = sig_action->k_sa_handler;
        if (handler == (void*)SIG_DFL || handler == (void*)SIG_IGN) {
            /* POSIX.1: dispositions of any signals that are ignored or set to the default are left
             * unchanged. On Linux, this rule applies to SIGCHLD as well. */
            continue;
        }

        /* app installed its own signal handler, reset it to default */
        sigaction_make_defaults(sig_action);
    }
    unlock(&current->signal_dispositions->lock);
}

static noreturn void sighandler_kill(int sig) {
    log_debug("killed by signal %d\n", sig & ~__WCOREDUMP_BIT);
    process_exit(0, sig);
}

static noreturn void sighandler_core(int sig) {
    /* NOTE: This implementation only indicates the core dump for wait4()
     *       and friends. No actual core-dump file is created. */
    sig = __WCOREDUMP_BIT | sig;
    sighandler_kill(sig);
}

typedef enum {
    SIGHANDLER_NONE,
    SIGHANDLER_KILL,
    SIGHANDLER_CORE,
} SIGHANDLER_T;

static const SIGHANDLER_T default_sighandler[NUM_SIGS] = {
    [SIGHUP    - 1] = SIGHANDLER_KILL,
    [SIGINT    - 1] = SIGHANDLER_KILL,
    [SIGQUIT   - 1] = SIGHANDLER_CORE,
    [SIGILL    - 1] = SIGHANDLER_CORE,
    [SIGTRAP   - 1] = SIGHANDLER_CORE,
    [SIGABRT   - 1] = SIGHANDLER_CORE,
    [SIGBUS    - 1] = SIGHANDLER_CORE,
    [SIGFPE    - 1] = SIGHANDLER_CORE,
    [SIGKILL   - 1] = SIGHANDLER_KILL,
    [SIGUSR1   - 1] = SIGHANDLER_KILL,
    [SIGSEGV   - 1] = SIGHANDLER_CORE,
    [SIGUSR2   - 1] = SIGHANDLER_KILL,
    [SIGPIPE   - 1] = SIGHANDLER_KILL,
    [SIGALRM   - 1] = SIGHANDLER_KILL,
    [SIGTERM   - 1] = SIGHANDLER_KILL,
    [SIGSTKFLT - 1] = SIGHANDLER_KILL,
    [SIGCHLD   - 1] = SIGHANDLER_NONE,
    [SIGCONT   - 1] = SIGHANDLER_NONE,
    [SIGSTOP   - 1] = SIGHANDLER_NONE,
    [SIGTSTP   - 1] = SIGHANDLER_NONE,
    [SIGTTIN   - 1] = SIGHANDLER_NONE,
    [SIGTTOU   - 1] = SIGHANDLER_NONE,
    [SIGURG    - 1] = SIGHANDLER_NONE,
    [SIGXCPU   - 1] = SIGHANDLER_CORE,
    [SIGXFSZ   - 1] = SIGHANDLER_CORE,
    [SIGVTALRM - 1] = SIGHANDLER_KILL,
    [SIGPROF   - 1] = SIGHANDLER_KILL,
    [SIGWINCH  - 1] = SIGHANDLER_NONE,
    [SIGIO     - 1] = SIGHANDLER_KILL,
    [SIGPWR    - 1] = SIGHANDLER_KILL,
    [SIGSYS    - 1] = SIGHANDLER_CORE,
};


static struct shim_signal_queue g_process_signal_queue = {0};
/* This lock should always be taken after thread lock (if both are needed). */
static struct shim_lock g_process_signal_queue_lock;
/*
 * This is just an optimization, not to have to check the queue for pending signals. This field can
 * be read atomically without any locks, to get approximate value, but to get exact you need to take
 * appropriate lock. Every store should be both atomic and behind a lock.
 */
static uint64_t g_process_pending_signals_cnt = 0;

/*
 * If host signal injection is enabled, this stores the injected signal. Note that we currently
 * support injecting only 1 instance of 1 signal only once, as this feature is meant only for
 * graceful termination of the user application (e.g. via SIGTERM).
 */
static int g_host_injected_signal = 0;
static bool g_inject_host_signal_enabled = false;

static bool is_rt_sq_empty(struct shim_rt_signal_queue* queue) {
    return queue->get_idx == queue->put_idx;
}

static bool has_standard_signal(struct shim_signal* signal_slot) {
    return signal_slot->siginfo.si_signo != 0;
}

static void recalc_pending_mask(struct shim_signal_queue* queue, int sig) {
    if (sig < SIGRTMIN) {
        if (!has_standard_signal(&queue->standard_signals[sig - 1])) {
            __sigdelset(&queue->pending_mask, sig);
        }
    } else {
        if (is_rt_sq_empty(&queue->rt_signal_queues[sig - SIGRTMIN])) {
            __sigdelset(&queue->pending_mask, sig);
        }
    }
}

void get_all_pending_signals(__sigset_t* set) {
    struct shim_thread* current = get_cur_thread();

    __sigemptyset(set);

    if (__atomic_load_n(&current->pending_signals, __ATOMIC_ACQUIRE) == 0
            && __atomic_load_n(&g_process_pending_signals_cnt, __ATOMIC_ACQUIRE) == 0) {
        return;
    }

    lock(&current->lock);
    lock(&g_process_signal_queue_lock);

    __sigorset(set, &current->signal_queue.pending_mask, &g_process_signal_queue.pending_mask);

    unlock(&g_process_signal_queue_lock);
    unlock(&current->lock);
}

bool have_pending_signals(void) {
    struct shim_thread* current = get_cur_thread();
    __sigset_t set;
    get_all_pending_signals(&set);

    lock(&current->lock);
    __signotset(&set, &set, &current->signal_mask);
    unlock(&current->lock);

    return !__sigisemptyset(&set) || __atomic_load_n(&current->time_to_die, __ATOMIC_ACQUIRE);
}

static bool append_standard_signal(struct shim_signal* queue_slot, struct shim_signal* signal) {
    if (has_standard_signal(queue_slot)) {
        return false;
    }

    *queue_slot = *signal;
    return true;
}

static bool append_rt_signal(struct shim_rt_signal_queue* queue, struct shim_signal** signal) {
    assert(queue->get_idx <= queue->put_idx);
    if (queue->get_idx >= ARRAY_SIZE(queue->queue)) {
        queue->get_idx -= ARRAY_SIZE(queue->queue);
        queue->put_idx -= ARRAY_SIZE(queue->queue);
    }

    if (queue->put_idx - queue->get_idx >= ARRAY_SIZE(queue->queue)) {
        return false;
    }

    queue->queue[queue->put_idx % ARRAY_SIZE(queue->queue)] = *signal;
    *signal = NULL;
    queue->put_idx++;
    return true;
}

static bool queue_append_signal(struct shim_signal_queue* queue, struct shim_signal** signal) {
    int sig = (*signal)->siginfo.si_signo;

    bool ret = false;
    if (sig < 1 || sig > NUM_SIGS) {
        ret = false;
    } else if (sig < SIGRTMIN) {
        ret = append_standard_signal(&queue->standard_signals[sig - 1], *signal);
    } else {
        ret = append_rt_signal(&queue->rt_signal_queues[sig - SIGRTMIN], signal);
    }

    if (ret) {
        __sigaddset(&queue->pending_mask, sig);
    }

    return ret;
}

static bool append_thread_signal(struct shim_thread* thread, struct shim_signal** signal) {
    lock(&thread->lock);
    bool ret = queue_append_signal(&thread->signal_queue, signal);
    if (ret) {
        (void)__atomic_add_fetch(&thread->pending_signals, 1, __ATOMIC_RELEASE);
    }
    unlock(&thread->lock);
    return ret;
}

static bool append_process_signal(struct shim_signal** signal) {
    lock(&g_process_signal_queue_lock);
    bool ret = queue_append_signal(&g_process_signal_queue, signal);
    if (ret) {
        (void)__atomic_add_fetch(&g_process_pending_signals_cnt, 1, __ATOMIC_RELEASE);
    }
    unlock(&g_process_signal_queue_lock);
    return ret;
}

static bool pop_standard_signal(struct shim_signal* queue_slot, struct shim_signal* signal) {
    if (!has_standard_signal(queue_slot)) {
        return false;
    }

    /* Some signal is set, copy it. */
    *signal = *queue_slot;

    /* Mark slot as empty. */
    queue_slot->siginfo.si_signo = 0;

    return true;
}

static bool pop_rt_signal(struct shim_rt_signal_queue* queue, struct shim_signal** signal) {
    assert(queue->get_idx <= queue->put_idx);

    if (queue->get_idx < queue->put_idx) {
        *signal = queue->queue[queue->get_idx % ARRAY_SIZE(queue->queue)];
        queue->get_idx++;
        return true;
    }
    return false;
}

void free_signal_queue(struct shim_signal_queue* queue) {
    /* We ignore standard signals - they are stored by value. */

    for (int sig = SIGRTMIN; sig <= NUM_SIGS; sig++) {
        struct shim_signal* signal;
        while (pop_rt_signal(&queue->rt_signal_queues[sig - SIGRTMIN], &signal)) {
            free(signal);
        }
    }
}

static void force_signal(siginfo_t* info) {
    struct shim_thread* current = get_cur_thread();

    current->forced_signal.siginfo = *info;
}

static bool have_forced_signal(void) {
    struct shim_thread* current = get_cur_thread();
    return current->forced_signal.siginfo.si_signo != 0;
}

static void get_forced_signal(struct shim_signal* signal) {
    struct shim_thread* current = get_cur_thread();
    *signal = current->forced_signal;
    current->forced_signal.siginfo.si_signo = 0;
}

static bool context_is_libos(PAL_CONTEXT* context) {
    uintptr_t ip = pal_context_get_ip(context);

    return (uintptr_t)&__load_address <= ip && ip < (uintptr_t)&__load_address_end;
}

static noreturn void internal_fault(const char* errstr, PAL_NUM addr, PAL_CONTEXT* context) {
    IDTYPE tid = get_cur_tid();
    PAL_NUM ip = pal_context_get_ip(context);

    if (context_is_libos(context))
        log_error("%s at 0x%08lx (IP = +0x%lx, VMID = %u, TID = %u)\n", errstr, addr,
                  (void*)ip - (void*)&__load_address, g_process_ipc_info.vmid,
                  is_internal_tid(tid) ? 0 : tid);
    else
        log_error("%s at 0x%08lx (IP = 0x%08lx, VMID = %u, TID = %u)\n", errstr, addr,
                  context ? ip : 0, g_process_ipc_info.vmid, is_internal_tid(tid) ? 0 : tid);

    DEBUG_BREAK_ON_FAILURE();
    DkProcessExit(1);
}

static void arithmetic_error_upcall(bool is_in_pal, PAL_NUM addr, PAL_CONTEXT* context) {
    __UNUSED(is_in_pal);
    assert(!is_in_pal);
    assert(context);

    if (is_internal_tid(get_cur_tid()) || context_is_libos(context)) {
        internal_fault("Internal arithmetic fault", addr, context);
    } else {
        log_debug("arithmetic fault at 0x%08lx\n", pal_context_get_ip(context));
        siginfo_t info = {
            .si_signo = SIGFPE,
            .si_code = FPE_INTDIV,
            .si_addr = (void*)addr,
        };
        force_signal(&info);
        handle_signal(context, /*old_mask_ptr=*/NULL);
    }
}

static void memfault_upcall(bool is_in_pal, PAL_NUM addr, PAL_CONTEXT* context) {
    __UNUSED(is_in_pal);
    assert(!is_in_pal);
    assert(context);

    shim_tcb_t* tcb = shim_get_tcb();
    assert(tcb);

    if (tcb->test_range.cont_addr && (void*)addr >= tcb->test_range.start &&
            (void*)addr <= tcb->test_range.end) {
        assert(context_is_libos(context));
        tcb->test_range.has_fault = true;
        pal_context_set_ip(context, (PAL_NUM)tcb->test_range.cont_addr);
        return;
    }

    if (is_internal_tid(get_cur_tid()) || context_is_libos(context)) {
        internal_fault("Internal memory fault", addr, context);
    }

    log_debug("memory fault at 0x%08lx (IP = 0x%08lx)\n", addr, pal_context_get_ip(context));

    siginfo_t info = {
        .si_addr = (void*)addr,
    };
    struct shim_vma_info vma_info;
    if (!lookup_vma((void*)addr, &vma_info)) {
        if (vma_info.flags & VMA_INTERNAL) {
            internal_fault("Internal memory fault with VMA", addr, context);
        }
        struct shim_handle* file = vma_info.file;
        if (file && file->type == TYPE_FILE) {
            /* If the mapping exceeds end of a file then return a SIGBUS. */
            uintptr_t eof_in_vma = (uintptr_t)vma_info.addr
                                   + (file->info.file.size - vma_info.file_offset);
            if (addr > eof_in_vma) {
                info.si_signo = SIGBUS;
                info.si_code = BUS_ADRERR;
            } else {
                info.si_signo = SIGSEGV;
                info.si_code = SEGV_ACCERR;
            }
        } else {
            info.si_signo = SIGSEGV;
            info.si_code = SEGV_ACCERR;
        }

        if (file) {
            put_handle(file);
        }
    } else {
        info.si_signo = SIGSEGV;
        info.si_code = SEGV_MAPERR;
    }

    force_signal(&info);
    handle_signal(context, /*old_mask_ptr=*/NULL);
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
    static int sgx_pal = 0;
    static int inited  = 0;

    if (!__atomic_load_n(&inited, __ATOMIC_RELAXED)) {
        /* Ensure that `sgx_pal` is updated before `inited`. */
        __atomic_store_n(&sgx_pal, !strcmp(g_pal_control->host_type, "Linux-SGX"),
                         __ATOMIC_RELAXED);
        COMPILER_BARRIER();
        __atomic_store_n(&inited, 1, __ATOMIC_RELAXED);
    }

    return __atomic_load_n(&sgx_pal, __ATOMIC_RELAXED) != 0;
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
#ifdef UBSAN
__attribute__((no_sanitize("undefined")))
#endif
bool test_user_memory(void* addr, size_t size, bool write) {
    if (!size)
        return false;

    if (!access_ok(addr, size))
        return true;

    if (!g_check_invalid_ptrs)
        return false;

    /* SGX path: check if [addr, addr+size) is addressable (in some VMA) */
    if (is_sgx_pal())
        return !is_in_adjacent_user_vmas(addr, size);

    /* Non-SGX path: check if [addr, addr+size) is addressable by touching
     * a byte of each page; invalid access will be caught in memfault_upcall */
    shim_tcb_t* tcb = shim_get_tcb();
    assert(tcb && tcb->tp);

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
    return has_fault;
}

/*
 * This function tests a user string with unknown length. It only tests
 * whether the memory is readable.
 */
#ifdef UBSAN
__attribute__((no_sanitize("undefined")))
#endif
bool test_user_string(const char* addr) {
    if (!access_ok(addr, 1))
        return true;

    if (!g_check_invalid_ptrs)
        return false;

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
    return has_fault;
}

static void illegal_upcall(bool is_in_pal, PAL_NUM addr, PAL_CONTEXT* context) {
    __UNUSED(is_in_pal);
    assert(!is_in_pal);
    assert(context);

    struct shim_vma_info vma_info = {.file = NULL};
    if (is_internal(get_cur_thread()) || context_is_libos(context)
            || lookup_vma((void*)addr, &vma_info) || (vma_info.flags & VMA_INTERNAL)) {
        internal_fault("Illegal instruction during Graphene internal execution", addr, context);
    }

    if (vma_info.file) {
        put_handle(vma_info.file);
    }

    /* Emulate syscall instruction, which is prohibited in Linux-SGX PAL and raises a SIGILL. */
    if (!maybe_emulate_syscall(context)) {
        void* rip = (void*)pal_context_get_ip(context);
        log_debug("Illegal instruction during app execution at %p; delivering to app\n", rip);
        siginfo_t info = {
            .si_signo = SIGILL,
            .si_code = ILL_ILLOPC,
            .si_addr = (void*)addr,
        };
        force_signal(&info);
        handle_signal(context, /*old_mask_ptr=*/NULL);
    }
    /* else syscall was emulated. */
}

static void quit_upcall(bool is_in_pal, PAL_NUM addr, PAL_CONTEXT* context) {
    __UNUSED(addr);

    if (!g_inject_host_signal_enabled) {
        return;
    }

    int sig = 0;
    static_assert(SAME_TYPE(g_host_injected_signal, sig), "types must match");
    if (!__atomic_compare_exchange_n(&g_host_injected_signal, &sig, SIGTERM,
                                     /*weak=*/false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
        /* We already have 1 injected signal, bail out. */
        return;
    }

    if (is_internal(get_cur_thread()) || context_is_libos(context) || is_in_pal) {
        return;
    }
    handle_signal(context, /*old_mask_ptr=*/NULL);
}

static void interrupted_upcall(bool is_in_pal, PAL_NUM addr, PAL_CONTEXT* context) {
    __UNUSED(addr);

    if (is_internal(get_cur_thread()) || context_is_libos(context) || is_in_pal) {
        return;
    }
    handle_signal(context, /*old_mask_ptr=*/NULL);
}

int init_signal_handling(void) {
    if (!create_lock(&g_process_signal_queue_lock)) {
        return -ENOMEM;
    }

    int64_t allow_injection = 0;
    int ret = toml_int_in(g_manifest_root, "sys.enable_sigterm_injection", /*defaultval=*/0,
                          &allow_injection);
    if (ret < 0 || (allow_injection != 0 && allow_injection != 1)) {
        log_error("Cannot parse 'sys.enable_sigterm_injection' (the value must be 0 or 1)\n");
        return -EINVAL;
    }
    g_inject_host_signal_enabled = !!allow_injection;

    int64_t check_invalid_ptrs_int;
    ret = toml_int_in(g_manifest_root, "libos.check_invalid_pointers",
                      /*defaultval=*/1, &check_invalid_ptrs_int);
    if (ret < 0 || (check_invalid_ptrs_int != 0 && check_invalid_ptrs_int != 1)) {
        log_error("Cannot parse 'libos.check_invalid_pointers' (the value must be 0 or 1)\n");
        return -EINVAL;
    }
    g_check_invalid_ptrs = !!check_invalid_ptrs_int;

    DkSetExceptionHandler(&arithmetic_error_upcall, PAL_EVENT_ARITHMETIC_ERROR);
    DkSetExceptionHandler(&memfault_upcall,         PAL_EVENT_MEMFAULT);
    DkSetExceptionHandler(&illegal_upcall,          PAL_EVENT_ILLEGAL);
    DkSetExceptionHandler(&quit_upcall,             PAL_EVENT_QUIT);
    DkSetExceptionHandler(&interrupted_upcall,      PAL_EVENT_INTERRUPTED);
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

/* XXX: This function assumes that the stack is growing towards lower addresses. */
bool is_on_altstack(uintptr_t sp, stack_t* alt_stack) {
    uintptr_t alt_sp = (uintptr_t)alt_stack->ss_sp;
    uintptr_t alt_sp_end = alt_sp + alt_stack->ss_size;
    /*
     * If `alt_sp == sp` then either the alternative stack is full or we have another stack
     * allocated just above it (at lower address), which is empty and about to be used. Let's
     * pretend it is always the second case: overflowing the alternative stack is undefined behavior
     * and chances for reaching exactly the top of the stack without overflowing it are minimal.
     */
    if (alt_sp < sp && sp <= alt_sp_end) {
        return true;
    }
    return false;
}

/* XXX: This function assumes that the stack is growing towards lower addresses. */
uintptr_t get_stack_for_sighandler(uintptr_t sp, bool use_altstack) {
    struct shim_thread* current = get_cur_thread();
    stack_t* alt_stack = &current->signal_altstack;

    if (!use_altstack || alt_stack->ss_flags & SS_DISABLE || alt_stack->ss_size == 0) {
        /* No alternative stack. */
        return sp - RED_ZONE_SIZE;
    }

    if (is_on_altstack(sp, alt_stack)) {
        /* We are currently running on alternative stack - just reuse it. */
        return sp - RED_ZONE_SIZE;
    }

    return (uintptr_t)alt_stack->ss_sp + alt_stack->ss_size;
}

/*
 * XXX(borysp): This function handles one pending, non-blocked, non-ignored signal at a time, while,
 * I believe, normal Linux creates sigframes for all pending, non-blocked, non-ignored signals at
 * once.
 * Note: each signal handler (at least on Linux x86_64) issues a `rt_sigreturn` syscall to return
 * back to the normal context; upon intercepting this syscall by LibOS, `handle_signal` will be
 * called again. This way all pending, non-blocked, non-ignored signals will be handled one by one,
 * unless the user app changes context in any other way (e.g. `swapcontext`), in which case the next
 * signal might be delayed until the next issued syscall.
 */
bool handle_signal(PAL_CONTEXT* context, __sigset_t* old_mask_ptr) {
    struct shim_thread* current = get_cur_thread();
    assert(current);
    assert(!is_internal(current));
    assert(!context_is_libos(context) || pal_context_get_ip(context) == (uint64_t)&syscalldb);

    if (__atomic_load_n(&current->time_to_die, __ATOMIC_ACQUIRE)) {
        thread_exit(/*error_code=*/0, /*term_signal=*/0);
    }

    struct shim_signal signal = { 0 };
    if (have_forced_signal()) {
        get_forced_signal(&signal);
    } else if (__atomic_load_n(&current->pending_signals, __ATOMIC_ACQUIRE)
               || __atomic_load_n(&g_process_pending_signals_cnt, __ATOMIC_ACQUIRE)) {
        lock(&current->lock);
        lock(&g_process_signal_queue_lock);
        for (int sig = 1; sig <= NUM_SIGS; sig++) {
            if (!__sigismember(&current->signal_mask, sig)) {
                bool got = false;
                bool was_process = false;
                /* First try to handle signals targeted at this thread, then processwide. */
                if (sig < SIGRTMIN) {
                    got = pop_standard_signal(&current->signal_queue.standard_signals[sig - 1],
                                              &signal);
                    if (!got) {
                        got = pop_standard_signal(&g_process_signal_queue.standard_signals[sig - 1],
                                                  &signal);
                        was_process = true;
                    }
                } else {
                    struct shim_signal* signal_ptr = NULL;
                    got = pop_rt_signal(&current->signal_queue.rt_signal_queues[sig - SIGRTMIN],
                                        &signal_ptr);
                    if (!got) {
                        assert(signal_ptr == NULL);
                        got =
                            pop_rt_signal(&g_process_signal_queue.rt_signal_queues[sig - SIGRTMIN],
                                          &signal_ptr);
                        was_process = true;
                    }
                    if (signal_ptr) {
                        assert(got);
                        signal = *signal_ptr;
                        free(signal_ptr);
                    }
                }

                if (got) {
                    if (was_process) {
                        (void)__atomic_sub_fetch(&g_process_pending_signals_cnt, 1,
                                                 __ATOMIC_RELEASE);
                        recalc_pending_mask(&g_process_signal_queue, sig);
                    } else {
                        (void)__atomic_sub_fetch(&current->pending_signals, 1, __ATOMIC_RELEASE);
                        recalc_pending_mask(&current->signal_queue, sig);
                    }
                    break;
                }
            }
        }
        unlock(&g_process_signal_queue_lock);
        unlock(&current->lock);
    } else if (__atomic_load_n(&g_host_injected_signal, __ATOMIC_RELAXED) != 0) {
        static_assert(NUM_SIGS < 0xff, "This code requires 0xff to be an invalid signal number");
        int sig = __atomic_exchange_n(&g_host_injected_signal, 0xff, __ATOMIC_RELAXED);
        if (sig != 0xff) {
            signal.siginfo.si_signo = sig;
            signal.siginfo.si_code = SI_USER;
        }
    }

    int sig = signal.siginfo.si_signo;
    if (!sig) {
        return false;
    }

    bool ret = false;
    lock(&current->signal_dispositions->lock);
    struct __kernel_sigaction* sa = &current->signal_dispositions->actions[sig - 1];

    void* handler = sa->k_sa_handler;
    if (handler == SIG_DFL) {
        if (default_sighandler[sig - 1] == SIGHANDLER_KILL) {
            unlock(&current->signal_dispositions->lock);
            sighandler_kill(sig);
            /* Unreachable. */
        } else if (default_sighandler[sig - 1] == SIGHANDLER_CORE) {
            unlock(&current->signal_dispositions->lock);
            sighandler_core(sig);
            /* Unreachable. */
        }
        assert(default_sighandler[sig - 1] == SIGHANDLER_NONE);
        handler = SIG_IGN;
    }
    if (handler != SIG_IGN) {
        /* User provided handler. */
        assert(sa->sa_flags & SA_RESTORER);

        long sysnr = shim_get_tcb()->context.syscall_nr;
        if (sysnr >= 0) {
            switch (pal_context_get_retval(context)) {
                case -ERESTARTNOHAND:
                    pal_context_set_retval(context, -EINTR);
                    break;
                case -ERESTARTSYS:
                    if (!(sa->sa_flags & SA_RESTART)) {
                        pal_context_set_retval(context, -EINTR);
                        break;
                    }
                    /* Fallthrough */
                case -ERESTARTNOINTR:
                    restart_syscall(context, (uint64_t)sysnr);
                    break;
                default:
                    break;
            }
        }

        __sigset_t new_mask = sa->sa_mask;
        if (!(sa->sa_flags & SA_NODEFER)) {
            __sigaddset(&new_mask, sig);
        }
        clear_illegal_signals(&new_mask);

        __sigset_t old_mask;
        lock(&current->lock);
        get_sig_mask(current, &old_mask);
        set_sig_mask(current, &new_mask);
        unlock(&current->lock);

        prepare_sigframe(context, &signal.siginfo, handler, sa->sa_restorer,
                         !!(sa->sa_flags & SA_ONSTACK), old_mask_ptr ?: &old_mask);

        if (sa->sa_flags & SA_RESETHAND) {
            /* borysp: In my opinion it should be `sigaction_make_defaults(sa);`, but Linux does
             * this and LTP explicitly tests for this ... */
            sa->k_sa_handler = SIG_DFL;
        }

        ret = true;
    }
    unlock(&current->signal_dispositions->lock);

    if (!ret) {
        /* We have seen an ignored signal, retry. */
        return handle_signal(context, old_mask_ptr);
    }

    return true;
}

int append_signal(struct shim_thread* thread, siginfo_t* info) {
    assert(info);

    // TODO: ignore SIGCHLD even if it's masked, when handler is set to SIG_IGN (probably not here)

    /* For real-time signal we save a pointer to a signal object, so we need to allocate it here.
     * If this is a standard signal, this will be freed at return from this function. */
    struct shim_signal* signal = malloc(sizeof(*signal));
    if (!signal) {
        return -ENOMEM;
    }

    signal->siginfo = *info;

    if (thread) {
        if (append_thread_signal(thread, &signal)) {
            goto out;
        }
    } else {
        if (append_process_signal(&signal)) {
            goto out;
        }
    }

    if (thread) {
        log_debug("Signal %d queue of thread %u is full, dropping incoming signal\n",
                  info->si_signo, thread->tid);
    } else {
        log_debug("Signal %d queue of process is full, dropping incoming signal\n",
                  info->si_signo);
    }
    /* This is counter-intuitive, but we report success here: after all signal was successfully
     * delivered, just the queue was full. */
out:
    free(signal);
    return 0;
}
