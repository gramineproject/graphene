/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs that allocate, free or protect virtual memory.
 */

#include <asm/fcntl.h>
#include <asm/mman.h>

#include "api.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_flags_conv.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"

bool _DkCheckMemoryMappable(const void* addr, size_t size) {
    return (addr < DATA_END && addr + size > TEXT_START);
}

int _DkVirtualMemoryAlloc(void** paddr, size_t size, int alloc_type, int prot) {
    assert(WITHIN_MASK(alloc_type, PAL_ALLOC_MASK));
    assert(WITHIN_MASK(prot,       PAL_PROT_MASK));

    void* addr = *paddr;
    void* mem = addr;

    int flags = PAL_MEM_FLAGS_TO_LINUX(alloc_type, prot | PAL_PROT_WRITECOPY);
    prot = PAL_PROT_TO_LINUX(prot);

    flags |= MAP_ANONYMOUS | (addr ? MAP_FIXED : 0);
    mem = (void*)ARCH_MMAP(addr, size, prot, flags, -1, 0);

    if (IS_ERR_P(mem))
        return unix_to_pal_error(ERRNO_P(mem));

    *paddr = mem;
    return 0;
}

int _DkVirtualMemoryFree(void* addr, size_t size) {
    int ret = INLINE_SYSCALL(munmap, 2, addr, size);

    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : 0;
}

int _DkVirtualMemoryProtect(void* addr, size_t size, int prot) {
    int ret = INLINE_SYSCALL(mprotect, 3, addr, size, PAL_PROT_TO_LINUX(prot));
    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : 0;
}

static int read_proc_meminfo(const char* key, unsigned long* val) {
    int fd = INLINE_SYSCALL(open, 3, "/proc/meminfo", O_RDONLY, 0);

    if (IS_ERR(fd))
        return -PAL_ERROR_DENIED;

    char buffer[40];
    int ret = 0;
    size_t n;
    size_t r = 0;
    size_t len = strlen(key);

    ret = -PAL_ERROR_DENIED;
    while (1) {
        ret = INLINE_SYSCALL(read, 3, fd, buffer + r, 40 - r);
        if (IS_ERR(ret)) {
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

    INLINE_SYSCALL(close, 1, fd);
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
