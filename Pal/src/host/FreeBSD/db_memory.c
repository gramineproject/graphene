/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

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
#include "pal_freebsd_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_freebsd.h"
#include "pal_error.h"
#include "pal_debug.h"
#include "api.h"

#include <sys/mman.h>
#include <sys/sysctl.h>
#include <sys/vmmeter.h>

bool _DkCheckMemoryMappable (const void * addr, int size)
{
    return (addr <= DATA_END && addr + size >= TEXT_START);
}
int _DkVirtualMemoryAlloc (void ** paddr, uint64_t size, int alloc_type,
                           int prot)
{
    void * addr = *paddr, * mem = addr;

    int flags = HOST_FLAGS(alloc_type, prot|PAL_PROT_WRITECOPY);
    prot = HOST_PROT(prot);

    /* The memory should have MAP_PRIVATE and MAP_ANONYMOUS */
    flags |= MAP_ANONYMOUS|(addr ? MAP_FIXED : 0);
    mem = (void *) ARCH_MMAP(addr, size, prot, flags, -1, 0);

    if (IS_ERR_P(mem))
        return unix_to_pal_error(ERRNO_P(mem));

    *paddr = mem;
    return 0;
}

int _DkVirtualMemoryFree (void * addr, uint64_t size)
{
    int ret = INLINE_SYSCALL(munmap, 2, addr, size);

    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : 0;
}

int _DkVirtualMemoryProtect (void * addr, uint64_t size, int prot)
{
    int ret = INLINE_SYSCALL(mprotect, 3, addr, size, HOST_PROT(prot));

    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : 0;
}

#define MEM_TOTAL   1
#define MEM_FREE    2

#define VM_TOTAL    1

static int get_meminfo (int key, unsigned long * val)
{
    int mib[2], len;
    struct vmtotal vm;

    int ret = -PAL_ERROR_DENIED;

    switch(key){
        case MEM_TOTAL:
            mib[0] = CTL_HW;
            mib[1] = HW_REALMEM;
            len = sizeof(val);
            ret = INLINE_SYSCALL(__sysctl, 6, mib, 2, val, &len, NULL, 0);
            break;
        case MEM_FREE:
            mib[0] = CTL_VM;
            mib[1] = VM_TOTAL;
            len = sizeof(vm);
            ret = INLINE_SYSCALL(__sysctl, 6, mib, 2, &vm, &len, NULL, 0);
            *val = vm.t_free * 4096;
            break;
    }
    return ret;
}

unsigned long _DkMemoryQuota (void)
{
    if (bsd_state.memory_quota)
        return bsd_state.memory_quota;
    unsigned long quota = 0;
    if (get_meminfo(MEM_TOTAL, &quota) < 0)
        return 0;
    return quota * 1024;
}

unsigned long _DkMemoryAvailableQuota (void)
{
    unsigned long quota = 0;
    if (get_meminfo(MEM_FREE, &quota) < 0)
        return 0;
    return quota * 1024;
}
