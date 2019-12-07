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
 * db_object.c
 *
 * This file contains APIs for closing or polling PAL handles.
 */

#include "api.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"

/* _DkObjectsWaitAny for internal use. The function wait for any of the handle
   in the handle array. timeout can be set for the wait. */
int _DkObjectsWaitAny(int count, PAL_HANDLE* handleArray, int64_t timeout_us, PAL_HANDLE* polled) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* Improved version of _DkObjectsWaitAny(): wait for specific events on all handles in the handle
 * array and return multiple events (including errors) reported by the host. */
int _DkObjectsWaitEvents(int count, PAL_HANDLE* handleArray, PAL_FLG* events, PAL_FLG* ret_events,
                         int64_t timeout_us) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}
