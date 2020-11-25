/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * SGX profiling. This code maintains a hash map of IP locations encountered inside the enclave,
 * storing counters with elapsed time. The map is written out on program exit, along with map of
 * loaded objects, so that the resulting file can be converted to a report.
 */

#ifdef SGX_PROFILE

#include <assert.h>
#include <errno.h>
#include <stddef.h>

#include "cpu.h"
#include "perm.h"
#include "sgx_internal.h"
#include "spinlock.h"

struct counter {
    void* ip;
    uint64_t count;
    UT_hash_handle hh;
};

static spinlock_t g_profile_lock = INIT_SPINLOCK_UNLOCKED;
static struct counter* g_counters = NULL;
static uint64_t g_last_tsc = 0;

static int g_profile_enabled = false;
static int g_profile_all = false;
static int g_mem_fd = -1;
static uint64_t g_max_dt = 0;

/* Read memory from inside enclave (using /proc/self/mem). */
static void debug_read(void* dest, void* addr, size_t size) {
    int ret;
    size_t cur_size = size;
    void* cur_dest = dest;
    void* cur_addr = addr;

    while (cur_size > 0) {
        ret = INLINE_SYSCALL(pread, 4, g_mem_fd, cur_dest, cur_size, (off_t)cur_addr);

        if (IS_ERR(ret) && ERRNO(ret) == EINTR)
            continue;

        if (IS_ERR(ret)) {
            SGX_DBG(DBG_E, "debug_read: error reading %lu bytes at %p: %d\n", size, addr, ERRNO(ret));
            INLINE_SYSCALL(exit_group, 1, ERRNO(ret));
        }

        if (ret == 0) {
            SGX_DBG(DBG_E, "debug_read: EOF reading %lu bytes at %p\n", size, addr);
            INLINE_SYSCALL(exit_group, 1, 255);
        }

        assert(ret > 0);
        assert((unsigned)ret <= cur_size);
        cur_size -= ret;
        cur_dest += ret;
        cur_addr += ret;
    }
}

static void* get_sgx_ip(void* tcs) {
    uint64_t ossa;
    uint32_t cssa;
    debug_read(&ossa, tcs + 16, sizeof(ossa));
    debug_read(&cssa, tcs + 24, sizeof(cssa));

    void* gpr_addr = (void*)(
        g_pal_enclave.baseaddr
        + ossa + cssa * g_pal_enclave.ssaframesize
        - sizeof(sgx_pal_gpr_t));

    uint64_t rip;
    debug_read(&rip, gpr_addr + offsetof(sgx_pal_gpr_t, rip), sizeof(rip));

    return (void*)rip;
}

#define CPUID_LEAF_TSC_FREQ 0x15

static uint64_t get_tsc_hz(void) {
    uint32_t words[PAL_CPUID_WORD_NUM];
    uint64_t crys_hz;

    cpuid(CPUID_LEAF_TSC_FREQ, 0, words);
    if (words[PAL_CPUID_WORD_EBX] > 0 && words[PAL_CPUID_WORD_EAX] > 0) {
        /* nominal frequency of the core crystal clock in kHz */
        crys_hz = words[PAL_CPUID_WORD_ECX];
        if (crys_hz > 0) {
            return crys_hz * words[PAL_CPUID_WORD_EBX] / words[PAL_CPUID_WORD_EAX];
        }
    }
    return 0;
}

int sgx_profile_init(bool all) {
    assert(!g_profile_enabled);
    assert(g_mem_fd == -1);

    uint64_t tsc_hz = get_tsc_hz();
    if (tsc_hz == 0) {
        SGX_DBG(DBG_E, "sgx_profile_init: failed to get TSC frequency\n");
        return -ENOSYS;
    }

    // Assume Linux scheduler will normally interrupt the enclave 4 ms, or 250 times per second.
    g_max_dt = tsc_hz / 250;

    int ret = INLINE_SYSCALL(open, 3, "/proc/self/mem", O_RDONLY | O_LARGEFILE, 0);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "sgx_profile_init: opening /proc/self/mem failed: %d\n", ERRNO(ret));
        return ret;
    }
    g_mem_fd = ret;
    g_profile_enabled = true;
    g_profile_all = all;
    return 0;
}

/*
 * Shut down profiling and write out data to a file.

 * The file will contain two kinds of lines:
 * - "counter 0x<addr> <count>": counter value
 * - "file 0x<addr> <path>": address of shared object loaded inside enclave
 */
void sgx_profile_finish(void) {
    int ret;

    if (!g_profile_enabled)
        return;

    char buf[64];
    if (g_profile_all)
        snprintf(buf, sizeof(buf), "sgx-profile-%d.data", g_pal_enclave.pal_sec.pid);
    else
        snprintf(buf, sizeof(buf), "sgx-profile.data");
    SGX_DBG(DBG_I, "writing profile data to %s\n", buf);

    int fd = INLINE_SYSCALL(open, 3, buf, O_WRONLY | O_TRUNC | O_CREAT, PERM_rw_______);
    if (IS_ERR(fd)) {
        SGX_DBG(DBG_E, "sgx_profile_finish: error opening file: %d\n", -fd);
        goto out;
    }

    // Write out counters
    struct counter* counter;
    struct counter* tmp;
    HASH_ITER(hh, g_counters, counter, tmp) {
        pal_fdprintf(fd, "counter %p %lu\n", counter->ip, counter->count);
        HASH_DEL(g_counters, counter);
        free(counter);
    }

    // Write out debug_map (unfortunately we have to read it from enclave memory)
    if (g_pal_enclave.debug_map) {
        struct debug_map* _Atomic pmap;
        debug_read(&pmap, g_pal_enclave.debug_map, sizeof(pmap));

        while (pmap) {
            struct debug_map map;
            debug_read(&map, pmap, sizeof(map));

            pal_fdprintf(fd, "file %p ", map.load_addr);

            // Read file_name byte by byte until we encounter null terminator, and write it out
            char* file_name = map.file_name;
            char c;
            do {
                debug_read(&c, file_name, sizeof(c));
                pal_fdprintf(fd, "%c", c ?: '\n');
                file_name++;
            } while (c);

            pmap = map.next;
        }
    }

    ret = INLINE_SYSCALL(close, 1, fd);
    if (IS_ERR(ret))
        SGX_DBG(DBG_E, "sgx_profile_finish: closing %s failed: %d\n", buf, -ret);

out:
    ret = INLINE_SYSCALL(close, 1, g_mem_fd);
    if (IS_ERR(ret))
        SGX_DBG(DBG_E, "sgx_profile_finish: closing /proc/self/mem failed: %d\n", -ret);
    g_mem_fd = -1;
    g_profile_enabled = false;
}

/*
 * Update counters after exit from enclave.
 *
 * We use RDTSC to measure time since the last measurement, because in some cases the asynchronous
 * exits happen more often (e.g. repeated page faults), and places causing these exits would be
 * inaccurately counted if we always increased counters by 1.
 */
void sgx_profile_sample(void* tcs) {
    if (!g_profile_enabled)
        return;

    void* ip = get_sgx_ip(tcs);
    spinlock_lock(&g_profile_lock);

    uint64_t tsc = get_tsc();
    if (g_last_tsc > 0) {
        assert(tsc >= g_last_tsc);
        uint64_t dt = tsc - g_last_tsc;

        // Increase by at most g_max_dt ticks: if the last measurement is older, it means we
        // probably slept since then.
        if (dt > g_max_dt)
            dt = g_max_dt;

        struct counter* counter;
        HASH_FIND_PTR(g_counters, &ip, counter);
        if (counter) {
            counter->count += dt;
        } else {
            counter = malloc(sizeof(*counter));
            counter->ip = ip;
            counter->count = dt;
            HASH_ADD_PTR(g_counters, ip, counter);
        }
    }
    g_last_tsc = tsc;

    spinlock_unlock(&g_profile_lock);
}

#endif /* SGX_PROFILE */
