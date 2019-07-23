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
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"

bool _DkCheckMemoryMappable(const void* addr, size_t size) {
    return true;
}

int _DkVirtualMemoryAlloc(void** paddr, uint64_t size, int alloc_type, int prot) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkVirtualMemoryFree(void* addr, uint64_t size) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkVirtualMemoryProtect(void* addr, uint64_t size, int prot) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

unsigned long _DkMemoryQuota(void) {
    return 0;
}

unsigned long _DkMemoryAvailableQuota(void) {
    return 0;
}
