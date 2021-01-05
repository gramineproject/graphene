/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * SGX profiling. This code takes samples of running code and writes them out to a perf.data file
 * (see also sgx_perf_data.c).
 */

#ifdef DEBUG

#include <assert.h>
#include <errno.h>
#include <linux/limits.h>
#include <stddef.h>

#include "cpu.h"
#include "sgx_internal.h"
#include "sgx_tls.h"
#include "spinlock.h"
#include "string.h"

// FIXME: this is glibc realpath, declared here because the headers will conflict with PAL
char* realpath(const char* path, char* resolved_path);

#define NSEC_IN_SEC 1000000000

static spinlock_t g_perf_data_lock = INIT_SPINLOCK_UNLOCKED;
static struct perf_data* g_perf_data = NULL;

static bool g_profile_enabled = false;
static uint64_t g_profile_period;
static int g_mem_fd = -1;

/* Read memory from inside enclave (using /proc/self/mem). */
static ssize_t debug_read(void* dest, void* addr, size_t size) {
    ssize_t ret;
    size_t total = 0;

    while (total < size) {
        ret = INLINE_SYSCALL(pread, 4, g_mem_fd, (uint8_t*)dest + total, size - total,
                             (off_t)addr + total);

        if (IS_ERR(ret) && ERRNO(ret) == EINTR)
            continue;

        if (IS_ERR(ret))
            return ret;

        if (ret == 0)
            break;

        assert(ret > 0);
        assert((size_t)ret + total <= size);
        total += ret;
    }
    return total;
}

static int debug_read_all(void* dest, void* addr, size_t size) {
    ssize_t ret = debug_read(dest, addr, size);
    if (IS_ERR(ret))
        return ret;
    if ((size_t)ret < size)
        return -EINVAL;
    return 0;
}

static int get_sgx_gpr(sgx_pal_gpr_t* gpr, void* tcs) {
    int ret;
    uint64_t ossa;
    uint32_t cssa;
    ret = debug_read_all(&ossa, tcs + 16, sizeof(ossa));
    if (ret < 0)
        return ret;
    ret = debug_read_all(&cssa, tcs + 24, sizeof(cssa));
    if (ret < 0)
        return ret;

    void* gpr_addr = (void*)(
        g_pal_enclave.baseaddr
        + ossa + cssa * g_pal_enclave.ssaframesize
        - sizeof(*gpr));

    ret = debug_read_all(gpr, gpr_addr, sizeof(*gpr));
    if (ret < 0)
        return ret;

    return 0;
}

int sgx_profile_init(void) {
    int ret;

    assert(!g_profile_enabled);
    assert(g_mem_fd == -1);
    assert(!g_perf_data);

    g_profile_period = NSEC_IN_SEC / g_pal_enclave.profile_frequency;

    ret = INLINE_SYSCALL(open, 3, "/proc/self/mem", O_RDONLY | O_LARGEFILE, 0);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "sgx_profile_init: opening /proc/self/mem failed: %d\n", ret);
        goto out;
    }
    g_mem_fd = ret;

    struct perf_data* pd = pd_open(g_pal_enclave.profile_filename, g_pal_enclave.profile_with_stack);
    if (!pd) {
        SGX_DBG(DBG_E, "sgx_profile_init: pd_open failed\n");
        ret = -EINVAL;
        goto out;
    }
    g_perf_data = pd;

    pid_t pid = g_pal_enclave.pal_sec.pid;
    ret = pd_event_command(pd, "pal-sgx", pid, /*tid=*/pid);
    if (!pd) {
        SGX_DBG(DBG_E, "sgx_profile_init: reporting command failed: %d\n", ret);
        goto out;
    }

    g_profile_enabled = true;
    return 0;

out:
    if (g_mem_fd > 0) {
        int close_ret = INLINE_SYSCALL(close, 1, g_mem_fd);
        if (IS_ERR(close_ret))
            SGX_DBG(DBG_E, "sgx_profile_init: closing /proc/self/mem failed: %d\n",
                    ERRNO(close_ret));
        g_mem_fd = -1;
    }

    if (g_perf_data) {
        ssize_t close_ret = pd_close(g_perf_data);
        if (IS_ERR(close_ret))
            SGX_DBG(DBG_E, "sgx_profile_init: pd_close failed: %ld\n", close_ret);
            g_perf_data = NULL;
    }
    return ret;
}

void sgx_profile_finish(void) {
    int ret;
    ssize_t size;

    if (!g_profile_enabled)
        return;

    spinlock_lock(&g_perf_data_lock);

    size = pd_close(g_perf_data);
    if (IS_ERR(size))
        SGX_DBG(DBG_E, "sgx_profile_finish: pd_close failed: %ld\n", size);
    g_perf_data = NULL;

    spinlock_unlock(&g_perf_data_lock);

    ret = INLINE_SYSCALL(close, 1, g_mem_fd);
    if (IS_ERR(ret))
        SGX_DBG(DBG_E, "sgx_profile_finish: closing /proc/self/mem failed: %d\n", ret);
    g_mem_fd = -1;

    SGX_DBG(DBG_I, "Profile data written to %s (%lu bytes)\n", g_pal_enclave.profile_filename,
            size);

    g_profile_enabled = false;
}

static void sample_simple(void* tcs, pid_t pid, pid_t tid) {
    int ret;
    sgx_pal_gpr_t gpr;

    ret = get_sgx_gpr(&gpr, tcs);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "error reading GPR: %d\n", ret);
        return;
    }

    spinlock_lock(&g_perf_data_lock);
    ret = pd_event_sample_simple(g_perf_data, gpr.rip, pid, tid, g_profile_period);
    spinlock_unlock(&g_perf_data_lock);

    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "error recording sample: %d\n", ret);
    }
}

static void sample_stack(void* tcs, pid_t pid, pid_t tid) {
    int ret;
    sgx_pal_gpr_t gpr;

    ret = get_sgx_gpr(&gpr, tcs);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "error reading GPR: %d\n", ret);
        return;
    }

    uint8_t stack[PD_STACK_SIZE];
    size_t stack_size;
    ret = debug_read(stack, (void*)gpr.rsp, sizeof(stack));
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "error reading stack: %d\n", ret);
        return;
    }
    stack_size = ret;

    spinlock_lock(&g_perf_data_lock);
    ret = pd_event_sample_stack(g_perf_data, gpr.rip, pid, tid, g_profile_period,
                                &gpr, stack, stack_size);
    spinlock_unlock(&g_perf_data_lock);

    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "error recording sample: %d\n", ret);
    }
}

/*
 * Take a sample after an exit from enclave.
 *
 * Use CPU time to record a sample approximately every 'g_profile_period' nanoseconds. Note that we
 * rely on Linux scheduler to generate an AEX event 250 times per second (although other events may
 * cause an AEX to happen more often), so sampling frequency greater than 250 cannot be reliably
 * achieved.
 */
void sgx_profile_sample(void* tcs) {
    int ret;

    if (!g_profile_enabled)
        return;

    // Check current CPU time
    struct timespec ts;
    ret = INLINE_SYSCALL(clock_gettime, 2, CLOCK_THREAD_CPUTIME_ID, &ts);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "sgx_profile_sample: clock_gettime failed: %d\n", ret);
        return;
    }
    uint64_t sample_time = ts.tv_sec * NSEC_IN_SEC + ts.tv_nsec;

    // Compare and update last recorded time per thread
    PAL_TCB_URTS* tcb = get_tcb_urts();
    if (tcb->profile_sample_time == 0) {
        tcb->profile_sample_time = sample_time;
        return;
    }

    assert(sample_time >= tcb->profile_sample_time);
    // Report a sample, if necessary
    if (sample_time - tcb->profile_sample_time >= g_profile_period) {
        tcb->profile_sample_time = sample_time;

        // Report all events as the same PID so that they are grouped in report.
        pid_t pid = g_pal_enclave.pal_sec.pid;
        pid_t tid = pid;

        if (g_pal_enclave.profile_with_stack) {
            sample_stack(tcs, pid, tid);
        } else {
            sample_simple(tcs, pid, tid);
        }
    }
}

void sgx_profile_report_mmap(const char* filename, uint64_t addr, uint64_t len, uint64_t offset) {
    if (!g_profile_enabled)
        return;

    // Convert filename to absolute path - some tools (e.g. libunwind in 'perf report') refuse to
    // process relative paths.
    char buf[PATH_MAX];
    char* path = realpath(filename, buf);
    if (!path) {
        SGX_DBG(DBG_E, "sgx_profile_report_mmap: realpath(%s) failed\n", filename);
        return;
    }

    pid_t pid = g_pal_enclave.pal_sec.pid;

    spinlock_lock(&g_perf_data_lock);
    int ret = pd_event_mmap(g_perf_data, path, pid, addr, len, offset);
    spinlock_unlock(&g_perf_data_lock);
    if (IS_ERR(ret))
        SGX_DBG(DBG_E, "sgx_profile_report_mmap: pd_event_mmap failed: %d\n", ret);
}

#endif /* DEBUG */
