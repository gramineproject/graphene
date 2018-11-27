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
 * db_memory.c
 *
 * This files contains APIs that allocate, free or protect virtual memory.
 */

#include "pal_defs.h"
#include "pal_linux_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_error.h"
#include "pal_debug.h"
#include "api.h"

#include <asm/mman.h>
#include <asm/fcntl.h>

bool _DkCheckMemoryMappable (const void * addr, size_t size)
{
    return (addr < DATA_END && addr + size > TEXT_START);
}

int _DkVirtualMemoryAlloc (void ** paddr, size_t size, int alloc_type,
                           int prot)
{
    void * addr = *paddr, * mem = addr;

    int flags = HOST_FLAGS(alloc_type, prot|PAL_PROT_WRITECOPY);
    prot = HOST_PROT(prot);

    flags |= MAP_ANONYMOUS|(addr ? MAP_FIXED : 0);
    mem = (void *) ARCH_MMAP(addr, size, prot, flags, -1, 0);

    if (IS_ERR_P(mem))
        return unix_to_pal_error(ERRNO_P(mem));

    *paddr = mem;
    return 0;
}

int _DkVirtualMemoryFree (void * addr, size_t size)
{
    int ret = INLINE_SYSCALL(munmap, 2, addr, size);

    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : 0;
}

int _DkVirtualMemoryProtect (void * addr, size_t size, int prot)
{
    int ret = INLINE_SYSCALL(mprotect, 3, addr, size, HOST_PROT(prot));

    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : 0;
}

static int read_proc_meminfo (const char * key, unsigned long * val)
{
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

        for (n = r ; n < r + ret ; n++)
            if (buffer[n] == '\n')
                break;

        r += ret;
        if (n == r + ret || n <= len) {
            ret = -PAL_ERROR_INVAL;
            break;
        }

        if (!memcmp(key, buffer, len) && buffer[len] == ':') {
            for (size_t i = len + 1; i < n ; i++)
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

unsigned long _DkMemoryQuota (void)
{
    if (linux_state.memory_quota == (unsigned long) -1)
        return 0;

    if (linux_state.memory_quota)
        return linux_state.memory_quota;

    unsigned long quota = 0;
    if (read_proc_meminfo("MemTotal", &quota) < 0) {
        linux_state.memory_quota = (unsigned long) -1;
        return 0;
    }

    return (linux_state.memory_quota = quota * 1024);
}

unsigned long _DkMemoryAvailableQuota (void)
{
    unsigned long quota = 0;
    if (read_proc_meminfo("MemFree", &quota) < 0)
        return 0;
    return quota * 1024;
}
