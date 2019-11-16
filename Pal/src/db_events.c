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

PAL_HANDLE DkNotificationEventCreate(PAL_BOL initialState) {
    ENTER_PAL_CALL(DkNotificationEventCreate);

    PAL_HANDLE handle = NULL;
    int ret           = _DkEventCreate(&handle, initialState, true);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        handle = NULL;
    }

    LEAVE_PAL_CALL_RETURN(handle);
}

PAL_HANDLE DkSynchronizationEventCreate(PAL_BOL initialState) {
    ENTER_PAL_CALL(DkSynchronizationEventCreate);

    PAL_HANDLE handle = NULL;
    int ret           = _DkEventCreate(&handle, initialState, false);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        handle = NULL;
    }

    LEAVE_PAL_CALL_RETURN(handle);
}

/* DkEventDestroy deprecated, replaced by DkObjectClose */

void DkEventSet(PAL_HANDLE handle) {
    ENTER_PAL_CALL(DkEventSet);

    if (!handle || !IS_HANDLE_TYPE(handle, event)) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL();
    }

    int ret = _DkEventSet(handle, -1);

    if (ret < 0)
        _DkRaiseFailure(-ret);

    LEAVE_PAL_CALL();
}

void DkEventWait(PAL_HANDLE handle) {
    ENTER_PAL_CALL(DkEventWait);

    if (!handle || !IS_HANDLE_TYPE(handle, event)) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL();
    }

    int ret = _DkEventWait(handle);

    if (ret < 0)
        _DkRaiseFailure(-ret);

    LEAVE_PAL_CALL();
}

void DkEventClear(PAL_HANDLE handle) {
    ENTER_PAL_CALL(DkEventClear);

    if (!handle || !IS_HANDLE_TYPE(handle, event)) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL();
    }

    int ret = _DkEventClear(handle);

    if (ret < 0)
        _DkRaiseFailure(-ret);

    LEAVE_PAL_CALL();
}
