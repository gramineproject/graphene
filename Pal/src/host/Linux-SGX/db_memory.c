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
#include "pal_linux_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_security.h"
#include "pal_error.h"
#include "pal_debug.h"
#include "api.h"

#include <asm/mman.h>

#include "enclave_pages.h"

#define PAL_VMA_MAX     64

static struct pal_vma {
    void * top, * bottom;
} pal_vmas[PAL_VMA_MAX];

static unsigned int pal_nvmas = 0;
static struct spinlock pal_vma_lock;

bool _DkCheckMemoryMappable (const void * addr, int size)
{
    if (addr < DATA_END && addr + size > TEXT_START) {
        printf("address %p-%p is not mappable\n", addr, addr + size);
        return true;
    }

    _DkSpinLock(&pal_vma_lock);

    for (int i = 0 ; i < pal_nvmas ; i++)
        if (addr < pal_vmas[i].top && addr + size > pal_vmas[i].bottom) {
            printf("address %p-%p is not mappable\n", addr, addr + size);
            _DkSpinUnlock(&pal_vma_lock);
            return true;
        }

    _DkSpinUnlock(&pal_vma_lock);
    return false;
}

int _DkVirtualMemoryAlloc (void ** paddr, uint64_t size, int alloc_type, int prot)
{
    void * addr = *paddr, * mem;

    //int flags = HOST_FLAGS(alloc_type, prot|PAL_PROT_WRITECOPY);
    //prot = HOST_PROT(prot);
    /* The memory should have MAP_PRIVATE and MAP_ANONYMOUS */
    //flags |= MAP_ANONYMOUS|(addr ? MAP_FIXED : 0);
    //mem = (void *) ARCH_MMAP(addr, size, prot, flags, -1, 0);

    if ((alloc_type & PAL_ALLOC_INTERNAL) && addr)
        return -PAL_ERROR_INVAL;

    if (size == 0)
        asm volatile ("int $3");

    mem = get_reserved_pages(addr, size);
    if (!mem)
        return addr ? -PAL_ERROR_DENIED : -PAL_ERROR_NOMEM;
    if (addr && mem != addr) {
        // TODO: This case should be made impossible by fixing
        // `get_reserved_pages` semantics.
        free_pages(mem, size);
        return -PAL_ERROR_INVAL; // `addr` was unaligned.
    }

    memset(mem, 0, size);

    if (alloc_type & PAL_ALLOC_INTERNAL) {
        SGX_DBG(DBG_M, "pal allocates %p-%p for internal use\n", mem, mem + size);
        _DkSpinLock(&pal_vma_lock);
        assert(pal_nvmas < PAL_VMA_MAX);
        pal_vmas[pal_nvmas].bottom = mem;
        pal_vmas[pal_nvmas].top = mem + size;
        pal_nvmas++;
        _DkSpinUnlock(&pal_vma_lock);
    }

    *paddr = mem;
    return 0;
}

int _DkVirtualMemoryFree (void * addr, uint64_t size)
{

    if (sgx_is_within_enclave(addr, size)) {
        free_pages(addr, size);
    } else {
        /* Possible to have untrusted mapping. Simply unmap
           the memory outside the enclave */
        ocall_unmap_untrusted(addr, size);
    }
    return 0;
}

int _DkVirtualMemoryProtect (void * addr, uint64_t size, int prot)
{
    return 0;
}

unsigned long _DkMemoryQuota (void)
{
    return pal_sec.heap_max - pal_sec.heap_min;
}

extern struct atomic_int alloced_pages;
extern unsigned int pagesz;

unsigned long _DkMemoryAvailableQuota (void)
{
    return (pal_sec.heap_max - pal_sec.heap_min) -
        atomic_read(&alloced_pages) * pagesz;
}
