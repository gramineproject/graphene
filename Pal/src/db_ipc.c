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
 * db_ipc.c
 *
 * This file contains APIs for physical memory bulk copy across processes.
 */

#include "pal_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_error.h"
#include "api.h"

PAL_HANDLE
DkCreatePhysicalMemoryChannel (PAL_NUM * key)
{
    ENTER_PAL_CALL(DkCreatePhysicalMemoryChannel);

    PAL_HANDLE handle = NULL;
    int ret = _DkCreatePhysicalMemoryChannel(&handle, key);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        handle = NULL;
    }

    TRACE_HEAP(handle);
    LEAVE_PAL_CALL_RETURN(handle);
}

PAL_NUM
DkPhysicalMemoryCommit (PAL_HANDLE channel, PAL_NUM entries, PAL_PTR * addrs,
                        PAL_NUM * sizes, PAL_FLG flags)
{
    ENTER_PAL_CALL(DkPhysicalMemoryCommit);

    if (!addrs || !sizes || !channel || !IS_HANDLE_TYPE(channel, gipc)) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL_RETURN(0);
    }

    int ret = _DkPhysicalMemoryCommit(channel, entries, addrs, sizes, flags);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        ret = 0;
    }

    LEAVE_PAL_CALL_RETURN(ret);
}

PAL_NUM
DkPhysicalMemoryMap (PAL_HANDLE channel, PAL_NUM entries, PAL_PTR * addrs,
                     PAL_NUM * sizes, PAL_FLG * prots)
{
    ENTER_PAL_CALL(DkPhysicalMemoryMap);

    if (!sizes || !channel || !IS_HANDLE_TYPE(channel, gipc)) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL_RETURN(0);
    }

    int ret = _DkPhysicalMemoryMap(channel, entries, addrs, sizes, prots);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        ret = 0;
    }

    LEAVE_PAL_CALL_RETURN(ret);
}
