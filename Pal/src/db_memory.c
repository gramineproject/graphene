/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs that allocate, free or protect virtual memory.
 */

#include "api.h"
#include "pal.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"

int DkVirtualMemoryAlloc(PAL_PTR* addr, PAL_NUM size, PAL_FLG alloc_type, PAL_FLG prot) {
    assert(current_context_is_libos());
    current_context_set_pal();

    assert(addr);
    void* map_addr = *addr;

    if ((map_addr && !IS_ALLOC_ALIGNED_PTR(map_addr)) || !size || !IS_ALLOC_ALIGNED(size)) {
        current_context_set_libos();
        return -PAL_ERROR_INVAL;
    }

    if (map_addr && _DkCheckMemoryMappable(map_addr, size)) {
        current_context_set_libos();
        return -PAL_ERROR_DENIED;
    }

    int ret = _DkVirtualMemoryAlloc(addr, size, alloc_type, prot);

    current_context_set_libos();
    return ret;
}

int DkVirtualMemoryFree(PAL_PTR addr, PAL_NUM size) {
    assert(current_context_is_libos());
    current_context_set_pal();

    if (!addr || !size) {
        current_context_set_libos();
        return -PAL_ERROR_INVAL;
    }

    if (!IS_ALLOC_ALIGNED_PTR(addr) || !IS_ALLOC_ALIGNED(size)) {
        current_context_set_libos();
        return -PAL_ERROR_INVAL;
    }

    if (_DkCheckMemoryMappable((void*)addr, size)) {
        current_context_set_libos();
        return -PAL_ERROR_DENIED;
    }

    int ret = _DkVirtualMemoryFree((void*)addr, size);

    current_context_set_libos();
    return ret;
}

int DkVirtualMemoryProtect(PAL_PTR addr, PAL_NUM size, PAL_FLG prot) {
    assert(current_context_is_libos());
    current_context_set_pal();

    if (!addr || !size) {
        current_context_set_libos();
        return -PAL_ERROR_INVAL;
    }

    if (!IS_ALLOC_ALIGNED_PTR(addr) || !IS_ALLOC_ALIGNED(size)) {
        current_context_set_libos();
        return -PAL_ERROR_INVAL;
    }

    if (_DkCheckMemoryMappable((void*)addr, size)) {
        current_context_set_libos();
        return -PAL_ERROR_DENIED;
    }

    int ret = _DkVirtualMemoryProtect((void*)addr, size, prot);

    current_context_set_libos();
    return ret;
}

int add_preloaded_range(uintptr_t start, uintptr_t end, const char* comment) {
    size_t new_cnt = g_pal_control.preloaded_ranges_cnt + 1;
    void* new_ranges = malloc(new_cnt * sizeof(*g_pal_control.preloaded_ranges));
    if (!new_ranges) {
        return -PAL_ERROR_NOMEM;
    }

    if (g_pal_control.preloaded_ranges_cnt) {
        memcpy(new_ranges, g_pal_control.preloaded_ranges,
               g_pal_control.preloaded_ranges_cnt * sizeof(*g_pal_control.preloaded_ranges));
    }

    free(g_pal_control.preloaded_ranges);
    g_pal_control.preloaded_ranges = new_ranges;

    g_pal_control.preloaded_ranges[g_pal_control.preloaded_ranges_cnt].start = start;
    g_pal_control.preloaded_ranges[g_pal_control.preloaded_ranges_cnt].end = end;
    g_pal_control.preloaded_ranges[g_pal_control.preloaded_ranges_cnt].comment = comment;
    g_pal_control.preloaded_ranges_cnt++;

    return 0;
}
