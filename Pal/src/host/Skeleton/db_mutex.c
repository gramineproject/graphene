/* Copyright (C) 2019 The University of North Carolina at Chapel Hill
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
 * db_mutex.c
 *
 * This file contains APIs for closing or polling PAL handles.
 */

#include "pal_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_error.h"
#include "pal_debug.h"
#include "api.h"

int _DkMutexCreate (PAL_HANDLE * handle, int initialCount)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkMutexAcquire (PAL_HANDLE sem) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}
int _DkMutexAcquireTimeout (PAL_HANDLE sem, int timeout)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}
void _DkMutexRelease (PAL_HANDLE sem)
{
    1;
}

int _DkMutexGetCurrentCount (PAL_HANDLE sem)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}
