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
 * db_event.c
 *
 * This file contains implementation of Drawbridge event synchronization APIs.
 */

#include "api.h"
#include "pal.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"

int _DkEventCreate(PAL_HANDLE* event, bool initialState, bool isnotification) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

void _DkEventDestroy(PAL_HANDLE handle) {
    /* needs to be implemented */
}

int _DkEventSet(PAL_HANDLE event, int wakeup) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkEventWaitTimeout(PAL_HANDLE event, int64_t timeout_us) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkEventWait(PAL_HANDLE event) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkEventClear(PAL_HANDLE event) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int event_close(PAL_HANDLE handle) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int event_wait(PAL_HANDLE handle, int64_t timeout_us) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

struct handle_ops event_ops = {
    .close = &event_close,
    .wait  = &event_wait,
};
