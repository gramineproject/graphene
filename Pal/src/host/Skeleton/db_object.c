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

/* Wait on a synchronization handle and return 0 if this handle's event was triggered
 * or error code otherwise (e.g., due to timeout). */
int _DkSynchronizationObjectWait(PAL_HANDLE handle, int64_t timeout_us) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* Wait for specific events on all handles in the handle array and return multiple events
 * (including errors) reported by the host. Return 0 on success, PAL error on failure. */
int _DkStreamsWaitEvents(size_t count, PAL_HANDLE* handle_array, PAL_FLG* events, PAL_FLG* ret_events,
                         int64_t timeout_us) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}
