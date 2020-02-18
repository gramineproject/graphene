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
#include "pal_security.h"
#include "pal_error.h"
#include "pal_debug.h"
#include "spinlock.h"
#include "api.h"

#include <asm/mman.h>

#include "enclave_pages.h"

int _DkVirtualMemoryAlloc (void ** paddr, uint64_t size, int alloc_type, int prot)
{
    if (!WITHIN_MASK(prot, PAL_PROT_MASK))
        return -PAL_ERROR_INVAL;

    void* addr = *paddr;
    void* mem = *paddr;

    if ((alloc_type & PAL_ALLOC_INTERNAL) && addr)
        return -PAL_ERROR_INVAL;

    if (size == 0)
        __asm__ volatile ("int $3");

    int ret = get_reserved_pages(&mem, size, alloc_type & PAL_ALLOC_INTERNAL);
    if (ret < 0)
        return ret;
    if (addr && mem != addr) {
        // TODO: This case should be made impossible by fixing
        // `get_reserved_pages` semantics.
        free_pages(mem, size);
        return -PAL_ERROR_INVAL; // `addr` was unaligned.
    }
    memset(mem, 0, size);

    *paddr = mem;
    return 0;
}

int _DkVirtualMemoryFree (void * addr, uint64_t size)
{
    if (sgx_is_completely_within_enclave(addr, size)) {
        return free_pages(addr, size);
    } else {
        /* Possible to have untrusted mapping. Simply unmap
           the memory outside the enclave */
        ocall_munmap_untrusted(addr, size);
    }
    return 0;
}

int _DkVirtualMemoryProtect (void * addr, uint64_t size, int prot)
{
    if (!_DkCheckMemoryMappable(addr, size))
        return -PAL_ERROR_DENIED;

    static struct atomic_int at_cnt = {.counter = 0};

    if (atomic_cmpxchg(&at_cnt, 0, 1) == 0)
        SGX_DBG(DBG_M, "[Warning] DkVirtualMemoryProtect (0x%p, %lu, %d) is unimplemented",
                addr, size, prot);
    return 0;
}

unsigned long _DkMemoryQuota (void)
{
    return pal_sec.heap_max - pal_sec.heap_min;
}

extern struct atomic_int alloced_pages;
extern unsigned int g_page_size;

unsigned long _DkMemoryAvailableQuota (void)
{
    return (pal_sec.heap_max - pal_sec.heap_min) -
        atomic_read(&alloced_pages) * g_page_size;
}
