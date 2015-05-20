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

PAL_PTR
DkVirtualMemoryAlloc (PAL_PTR addr, PAL_NUM size, PAL_FLG alloc_type,
                      PAL_FLG prot)
{
    store_frame(VirtualMemoryAlloc);
    void * map_addr = (void *) addr;

    if ((addr && !ALLOC_ALIGNED(addr)) || !size || !ALLOC_ALIGNED(size))
        leave_frame(NULL, PAL_ERROR_INVAL);

    if (map_addr && _DkCheckMemoryMappable((void *) map_addr, size))
        leave_frame(NULL, PAL_ERROR_DENIED);

    int ret = _DkVirtualMemoryAlloc(&map_addr, size, alloc_type, prot);

    if (ret < 0)
        leave_frame(NULL, -ret);

    leave_frame(map_addr, 0);
}

void
DkVirtualMemoryFree (PAL_PTR addr, PAL_NUM size)
{
    store_frame(VirtualMemoryFree);

    if (!addr || !size)
        leave_frame(, PAL_ERROR_INVAL);

    if (!ALLOC_ALIGNED(addr) || !ALLOC_ALIGNED(size))
        leave_frame(, PAL_ERROR_INVAL);

    if (_DkCheckMemoryMappable((void *) addr, size))
        leave_frame(, PAL_ERROR_DENIED);

    int ret = _DkVirtualMemoryFree((void *) addr, size);

    if (ret < 0)
        leave_frame(, -ret);

    leave_frame(, 0);
}

PAL_BOL
DkVirtualMemoryProtect (PAL_PTR addr, PAL_NUM size, PAL_FLG prot)
{
    store_frame(VirtualMemoryProtect);

    if (!addr || !size)
        leave_frame(PAL_FALSE, PAL_ERROR_INVAL);

    if (!ALLOC_ALIGNED(addr) || !ALLOC_ALIGNED(size))
        leave_frame(PAL_FALSE, PAL_ERROR_INVAL);

    if (_DkCheckMemoryMappable((void *) addr, size))
        leave_frame(PAL_FALSE, PAL_ERROR_DENIED);

    int ret = _DkVirtualMemoryProtect((void *) addr, size, prot);

    if (ret < 0)
        leave_frame(PAL_FALSE, -ret);

    leave_frame(PAL_TRUE, 0);
}
