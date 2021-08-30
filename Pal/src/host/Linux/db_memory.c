/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs that allocate, free or protect virtual memory.
 */

#include <asm/fcntl.h>
#include <asm/mman.h>

#include "api.h"
#include "pal.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_flags_conv.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_linux_error.h"
#include "spinlock.h"

/* Internal-PAL memory is allocated in range [g_pal_internal_mem_addr, g_pal_internal_mem_size).
 * This range is "preloaded" (LibOS is notified that it cannot use this range), so there can be no
 * overlap between LibOS and internal-PAL allocations.
 *
 * Internal-PAL allocation is trivial: we simply increment a global pointer to the next available
 * memory region on allocations and do nothing on deallocations (and fail loudly if the limit
 * specified in the manifest is exceeded). This wastes memory, but we assume that internal-PAL
 * allocations are rare, and that PAL doesn't consume much memory anyway. In near future, we need to
 * rewrite Graphene allocation logic in PAL.
 */

static size_t g_pal_internal_mem_used = 0;
static spinlock_t g_pal_internal_mem_lock = INIT_SPINLOCK_UNLOCKED;

bool _DkCheckMemoryMappable(const void* addr, size_t size) {
    if (addr < DATA_END && addr + size > TEXT_START) {
        log_error("Address %p-%p is not mappable", addr, addr + size);
        return true;
    }
    return false;
}

int _DkVirtualMemoryAlloc(void** paddr, size_t size, int alloc_type, int prot) {
    assert(WITHIN_MASK(alloc_type, PAL_ALLOC_MASK));
    assert(WITHIN_MASK(prot,       PAL_PROT_MASK));

    void* addr = *paddr;

    if (alloc_type & PAL_ALLOC_INTERNAL) {
        size = ALIGN_UP(size, g_page_size);
        spinlock_lock(&g_pal_internal_mem_lock);
        if (size > g_pal_internal_mem_size - g_pal_internal_mem_used) {
            /* requested PAL-internal allocation would exceed the limit, fail */
            spinlock_unlock(&g_pal_internal_mem_lock);
            return -PAL_ERROR_NOMEM;
        }
        addr = g_pal_internal_mem_addr + g_pal_internal_mem_used;
        g_pal_internal_mem_used += size;
        assert(IS_ALIGNED(g_pal_internal_mem_used, g_page_size));
        spinlock_unlock(&g_pal_internal_mem_lock);
    }

    assert(addr);

    int flags = PAL_MEM_FLAGS_TO_LINUX(alloc_type, prot | PAL_PROT_WRITECOPY);
    prot = PAL_PROT_TO_LINUX(prot);

    flags |= MAP_ANONYMOUS | MAP_FIXED;
    addr = (void*)DO_SYSCALL(mmap, addr, size, prot, flags, -1, 0);

    if (IS_PTR_ERR(addr)) {
        /* note that we don't undo operations on `g_pal_internal_mem_used` in case of internal-PAL
         * allocations: this could lead to data races, so we just waste some memory on errors */
        return unix_to_pal_error(PTR_TO_ERR(addr));
    }

    *paddr = addr;
    return 0;
}

int _DkVirtualMemoryFree(void* addr, size_t size) {
    int ret = DO_SYSCALL(munmap, addr, size);
    return ret < 0 ? unix_to_pal_error(ret) : 0;
}

int _DkVirtualMemoryProtect(void* addr, size_t size, int prot) {
    int ret = DO_SYSCALL(mprotect, addr, size, PAL_PROT_TO_LINUX(prot));
    return ret < 0 ? unix_to_pal_error(ret) : 0;
}

static int read_proc_meminfo(const char* key, unsigned long* val) {
    int fd = DO_SYSCALL(open, "/proc/meminfo", O_RDONLY, 0);

    if (fd < 0)
        return -PAL_ERROR_DENIED;

    char buffer[40];
    int ret = 0;
    size_t n;
    size_t r = 0;
    size_t len = strlen(key);

    ret = -PAL_ERROR_DENIED;
    while (1) {
        ret = DO_SYSCALL(read, fd, buffer + r, 40 - r);
        if (ret < 0) {
            ret = -PAL_ERROR_DENIED;
            break;
        }

        for (n = r; n < r + ret; n++)
            if (buffer[n] == '\n')
                break;

        r += ret;
        if (n == r + ret || n <= len) {
            ret = -PAL_ERROR_INVAL;
            break;
        }

        if (!memcmp(key, buffer, len) && buffer[len] == ':') {
            for (size_t i = len + 1; i < n; i++)
                if (buffer[i] != ' ') {
                    *val = atol(buffer + i);
                    break;
                }
            ret = 0;
            break;
        }

        memmove(buffer, buffer + n + 1, r - n - 1);
        r -= n + 1;
    }

    DO_SYSCALL(close, fd);
    return ret;
}

unsigned long _DkMemoryQuota(void) {
    if (g_linux_state.memory_quota == (unsigned long)-1)
        return 0;

    if (g_linux_state.memory_quota)
        return g_linux_state.memory_quota;

    unsigned long quota = 0;
    if (read_proc_meminfo("MemTotal", &quota) < 0) {
        g_linux_state.memory_quota = (unsigned long)-1;
        return 0;
    }

    return (g_linux_state.memory_quota = quota * 1024);
}

unsigned long _DkMemoryAvailableQuota(void) {
    unsigned long quota = 0;
    if (read_proc_meminfo("MemFree", &quota) < 0)
        return 0;
    return quota * 1024;
}

/* Expects `line` to be in the same format as "/proc/self/maps" entries, i.e. starting with
 * "hexadecimalnumber-hexadecimalnumber", e.g. "1fe3-87cc ...". */
static int parse_line(const char* line, uintptr_t* start_ptr, uintptr_t* end_ptr) {
    const char* next = NULL;
    unsigned long val;

    if (str_to_ulong(line, 16, &val, &next) < 0)
        return -PAL_ERROR_INVAL;
    *start_ptr = val;

    assert(next);
    if (next[0] != '-')
        return -PAL_ERROR_INVAL;

    if (str_to_ulong(next + 1, 16, &val, &next) < 0)
        return -PAL_ERROR_INVAL;
    *end_ptr = val;
    return 0;
}

/* This function is very fragile w.r.t. "/proc/self/maps" file format. */
int get_vdso_and_vvar_ranges(uintptr_t* vdso_start, uintptr_t* vdso_end, uintptr_t* vvar_start,
                             uintptr_t* vvar_end) {
    int fd = DO_SYSCALL(open, "/proc/self/maps", O_RDONLY, 0);
    if (fd < 0) {
        return unix_to_pal_error(fd);
    }

    const char* vdso_str = "[vdso]";
    const size_t vdso_str_len = strlen(vdso_str);
    const char* vvar_str = "[vvar]";
    const size_t vvar_str_len = strlen(vvar_str);

    int ret = 0;
    /* Arbitrary size, must be big enough to hold lines containing "vdso" and "vvar". */
    char buf[0x100];
    size_t size = 0;
    ssize_t got = 0;
    do {
        /* There should be no failures or partial reads from this fd, but we need to loop anyway,
         * since the size of this file is unkown (and we have no way to check it). */
        got = DO_SYSCALL(read, fd, buf + size, sizeof(buf) - 1 - size);
        if (got < 0) {
            ret = unix_to_pal_error(got);
            goto out;
        }
        size += (size_t)got;
        buf[size] = '\0';

        char* line_end = strchr(buf, '\n');
        if (!line_end) {
            line_end = buf + size;
        }
        assert(line_end < buf + sizeof(buf));
        *line_end = '\0';

        if (!memcmp(vdso_str, line_end - vdso_str_len, vdso_str_len)) {
            ret = parse_line(buf, vdso_start, vdso_end);
            if (ret < 0)
                goto out;
        } else if (!memcmp(vvar_str, line_end - vvar_str_len, vvar_str_len)) {
            ret = parse_line(buf, vvar_start, vvar_end);
            if (ret < 0)
                goto out;
        }

        size_t new_size = 0;
        if (buf + size > line_end + 1) {
            new_size = buf + size - (line_end + 1);
            memmove(buf, line_end + 1, new_size);
        }
        size = new_size;
    } while (size > 0 || got > 0);

out:;
    int tmp_ret = unix_to_pal_error(DO_SYSCALL(close, fd));
    return ret ?: tmp_ret;
}

