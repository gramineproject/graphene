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

PAL_PTR
DkVirtualMemoryAlloc(PAL_PTR addr, PAL_NUM size, PAL_FLG alloc_type, PAL_FLG prot) {
    ENTER_PAL_CALL(DkVirtualMemoryAlloc);
    void* map_addr = (void*)addr;

    if ((addr && !IS_ALLOC_ALIGNED_PTR(addr)) || !size || !IS_ALLOC_ALIGNED(size)) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL_RETURN((PAL_PTR)NULL);
    }

    if (map_addr && _DkCheckMemoryMappable(map_addr, size)) {
        _DkRaiseFailure(PAL_ERROR_DENIED);
        LEAVE_PAL_CALL_RETURN((PAL_PTR)NULL);
    }

    int ret = _DkVirtualMemoryAlloc(&map_addr, size, alloc_type, prot);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        map_addr = NULL;
    }

    LEAVE_PAL_CALL_RETURN((PAL_PTR)map_addr);
}

void DkVirtualMemoryFree(PAL_PTR addr, PAL_NUM size) {
    ENTER_PAL_CALL(DkVirtualMemoryFree);

    if (!addr || !size) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL();
    }

    if (!IS_ALLOC_ALIGNED_PTR(addr) || !IS_ALLOC_ALIGNED(size)) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL();
    }

    if (_DkCheckMemoryMappable((void*)addr, size)) {
        _DkRaiseFailure(PAL_ERROR_DENIED);
        LEAVE_PAL_CALL();
    }

    int ret = _DkVirtualMemoryFree((void*)addr, size);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
    }

    LEAVE_PAL_CALL();
}

PAL_BOL
DkVirtualMemoryProtect(PAL_PTR addr, PAL_NUM size, PAL_FLG prot) {
    ENTER_PAL_CALL(DkVirtualMemoryProtect);

    if (!addr || !size) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    if (!IS_ALLOC_ALIGNED_PTR(addr) || !IS_ALLOC_ALIGNED(size)) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    if (_DkCheckMemoryMappable((void*)addr, size)) {
        _DkRaiseFailure(PAL_ERROR_DENIED);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    int ret = _DkVirtualMemoryProtect((void*)addr, size, prot);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    LEAVE_PAL_CALL_RETURN(PAL_TRUE);
}
