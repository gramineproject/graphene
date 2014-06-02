/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2014 OSCAR lab, Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * db_memory.c
 *
 * This files contains APIs that allocate, free or protect virtual memory.
 */

#include "pal_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_error.h"
#include "pal_debug.h"
#include "api.h"

bool check_memory_overlap (void * addr, size_t size)
{
    void * pal_min = pal_config.lib_text_start;
    void * pal_max = pal_config.lib_data_end;

    void * overlap_start = pal_min < addr ? addr : pal_min;
    void * overlap_end = addr + size < pal_max ? addr + size : pal_max;

    if (overlap_start < overlap_end) {
        printf("WARNING: Attempt to change PAL-internal memory!!!!"
               "   You seriously don't want to do this.\n");
        return true;
    }
    return false;
}

PAL_BUF
DkVirtualMemoryAlloc (PAL_BUF addr, PAL_NUM size, PAL_FLG alloc_type,
                      PAL_FLG prot)
{
    store_frame(VirtualMemoryAlloc);

    if ((addr && !ALLOC_ALIGNED(addr)) || !size || !ALLOC_ALIGNED(size)) {
        notify_failure(PAL_ERROR_INVAL);
        return NULL;
    }

    if (check_memory_overlap(addr, size)) {
        notify_failure(PAL_ERROR_DENIED);
        return NULL;
    }

    int ret = _DkVirtualMemoryAlloc(&addr, size, alloc_type, prot);

    if (ret < 0) {
        notify_failure(-ret);
        return NULL;
    }

    return addr;
}

void
DkVirtualMemoryFree (PAL_BUF addr, PAL_NUM size)
{
    store_frame(VirtualMemoryFree);

    if (!addr || !size) {
        notify_failure(PAL_ERROR_INVAL);
        return;
    }

    if (!ALLOC_ALIGNED(addr) || !ALLOC_ALIGNED(size)) {
        notify_failure(PAL_ERROR_INVAL);
        return;
    }

    if (check_memory_overlap(addr, size)) {
        notify_failure(PAL_ERROR_DENIED);
        return;
    }

    int ret = _DkVirtualMemoryFree(addr, size);
    if (ret < 0)
        notify_failure(-ret);
}

PAL_BOL
DkVirtualMemoryProtect (PAL_BUF addr, PAL_NUM size, PAL_FLG prot)
{
    store_frame(VirtualMemoryProtect);

    if (!addr || !size) {
        notify_failure(PAL_ERROR_INVAL);
        return PAL_FALSE;
    }

    if (!ALLOC_ALIGNED(addr) || !ALLOC_ALIGNED(size)) {
        notify_failure(PAL_ERROR_INVAL);
        return PAL_FALSE;
    }

    if (check_memory_overlap(addr, size)) {
        notify_failure(PAL_ERROR_DENIED);
        return NULL;
    }

    int ret = _DkVirtualMemoryProtect(addr, size, prot);

    if (ret < 0) {
        notify_failure(-ret);
        return PAL_FALSE;
    }

    return PAL_TRUE;
}
