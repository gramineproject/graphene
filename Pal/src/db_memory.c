/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs that allocate, free or protect virtual memory.
 */

#include "api.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"

int DkVirtualMemoryAlloc(PAL_PTR* addr, PAL_NUM size, PAL_FLG alloc_type, PAL_FLG prot) {
    assert(addr);
    void* map_addr = *addr;

    if ((map_addr && !IS_ALLOC_ALIGNED_PTR(map_addr)) || !size || !IS_ALLOC_ALIGNED(size)) {
        return -PAL_ERROR_INVAL;
    }

    if (map_addr && _DkCheckMemoryMappable(map_addr, size)) {
        return -PAL_ERROR_DENIED;
    }

    return _DkVirtualMemoryAlloc(addr, size, alloc_type, prot);
}

int DkVirtualMemoryFree(PAL_PTR addr, PAL_NUM size) {
    if (!addr || !size) {
        return -PAL_ERROR_INVAL;
    }

    if (!IS_ALLOC_ALIGNED_PTR(addr) || !IS_ALLOC_ALIGNED(size)) {
        return -PAL_ERROR_INVAL;
    }

    if (_DkCheckMemoryMappable((void*)addr, size)) {
        return -PAL_ERROR_DENIED;
    }

    return _DkVirtualMemoryFree((void*)addr, size);
}

int DkVirtualMemoryProtect(PAL_PTR addr, PAL_NUM size, PAL_FLG prot) {
    if (!addr || !size) {
        return -PAL_ERROR_INVAL;
    }

    if (!IS_ALLOC_ALIGNED_PTR(addr) || !IS_ALLOC_ALIGNED(size)) {
        return -PAL_ERROR_INVAL;
    }

    if (_DkCheckMemoryMappable((void*)addr, size)) {
        return -PAL_ERROR_DENIED;
    }

    return _DkVirtualMemoryProtect((void*)addr, size, prot);
}
