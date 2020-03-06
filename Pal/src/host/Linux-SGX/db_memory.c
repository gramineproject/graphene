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

#include "api.h"
#include "enclave_pages.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_security.h"

extern struct atomic_int g_alloced_pages;
extern size_t g_page_size;

bool _DkCheckMemoryMappable(const void* addr, size_t size) {
    if (addr < DATA_END && addr + size > TEXT_START) {
        SGX_DBG(DBG_E, "Address %p-%p is not mappable\n", addr, addr + size);
        return true;
    }

    /* FIXME: this function is almost useless now; note that _DkVirtualMemoryAlloc() checks whether
     * [addr, addr + size) overlaps with VMAs and errors out */

    return false;
}

int _DkVirtualMemoryAlloc(void** paddr, uint64_t size, int alloc_type, int prot) {
    if (!size || !WITHIN_MASK(prot, PAL_PROT_MASK))
        return -PAL_ERROR_INVAL;

    void* addr = *paddr;

    if ((alloc_type & PAL_ALLOC_INTERNAL) && addr) {
        /* internal-PAL memory allocation never uses fixed addresses */
        return -PAL_ERROR_INVAL;
    }

    void* mem = get_enclave_pages(addr, size, alloc_type & PAL_ALLOC_INTERNAL);
    if (!mem)
        return addr ? -PAL_ERROR_DENIED : -PAL_ERROR_NOMEM;

    memset(mem, 0, size);

    *paddr = mem;
    return 0;
}

int _DkVirtualMemoryFree(void* addr, uint64_t size) {
    if (sgx_is_completely_within_enclave(addr, size)) {
        int ret = free_enclave_pages(addr, size);
        if (ret < 0) {
            return ret;
        }
    } else {
        /* possible to have untrusted mapping, simply unmap memory outside the enclave */
        ocall_munmap_untrusted(addr, size);
    }
    return 0;
}

int _DkVirtualMemoryProtect(void* addr, uint64_t size, int prot) {
    __UNUSED(addr);
    __UNUSED(size);
    __UNUSED(prot);

    static struct atomic_int at_cnt = {.counter = 0};
    if (atomic_cmpxchg(&at_cnt, 0, 1) == 0)
        SGX_DBG(DBG_M, "[Warning] DkVirtualMemoryProtect is unimplemented in Linux-SGX PAL");
    return 0;
}

uint64_t _DkMemoryQuota(void) {
    return pal_sec.heap_max - pal_sec.heap_min;
}

uint64_t _DkMemoryAvailableQuota(void) {
    return (pal_sec.heap_max - pal_sec.heap_min) - atomic_read(&g_alloced_pages) * g_page_size;
}
