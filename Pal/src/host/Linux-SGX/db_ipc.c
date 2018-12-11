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
#include "pal_linux_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_error.h"

int gipc_open (__UNUSED PAL_HANDLE * handle, __UNUSED const char * type, __UNUSED const char * uri,
			__UNUSED int access, __UNUSED int share, __UNUSED int create, __UNUSED int options)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int gipc_close (__UNUSED PAL_HANDLE handle)
{
    return -PAL_ERROR_NOTIMPLEMENTED;

}

const char * gipc_getrealpath (__UNUSED PAL_HANDLE handle)
{
    return NULL;
}

struct handle_ops gipc_ops = {
        .getrealpath        = &gipc_getrealpath,
        .open               = &gipc_open,
        .close              = &gipc_close,
    };

int _DkCreatePhysicalMemoryChannel (__UNUSED PAL_HANDLE * handle, __UNUSED uint64_t * key)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkPhysicalMemoryCommit (__UNUSED PAL_HANDLE channel, __UNUSED int entries,
						__UNUSED PAL_PTR * addrs, __UNUSED PAL_NUM * sizes, __UNUSED int flags)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkPhysicalMemoryMap (__UNUSED PAL_HANDLE channel, __UNUSED int entries,
						__UNUSED PAL_PTR * addrs, __UNUSED PAL_NUM * sizes, __UNUSED PAL_FLG * prots)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}
