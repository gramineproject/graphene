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
#include "atomic.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"

/* Deprecated DkObjectReference. */

int _DkObjectClose(PAL_HANDLE objectHandle) {
    const struct handle_ops* ops = HANDLE_OPS(objectHandle);
    if (!ops)
        return -PAL_ERROR_BADHANDLE;

    int ret = 0;

    /* if the operation 'close' is defined, call the function. */
    if (ops->close)
        ret = ops->close(objectHandle);

    /*
     * Chia-Che 12/7/2017:
     *   _DkObjectClose will free the object, unless the handle has a 'close' operation, and the
     *   operation returns a non-zero value (e.g., 1 for skipping free() or -ERRNO).
     */
    if (!ret)
        free(objectHandle);

    return ret;
}

/* PAL call DkObjectClose: Close the given object handle. */
void DkObjectClose(PAL_HANDLE objectHandle) {
    ENTER_PAL_CALL(DkObjectClose);

    if (!objectHandle) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL();
    }

    int ret = _DkObjectClose(objectHandle);
    if (ret < 0)
        _DkRaiseFailure(-ret);

    LEAVE_PAL_CALL();
}

/* Wait on a synchronization handle and return true if this handle's event was triggered,
 * otherwise return false and additionally raise failure. */
PAL_BOL DkSynchronizationObjectWait(PAL_HANDLE handle, PAL_NUM timeout_us) {
    ENTER_PAL_CALL(DkSynchronizationObjectWait);

    if (!handle) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL_RETURN(NULL);
    }

    int ret = _DkSynchronizationObjectWait(handle, timeout_us);
    if (ret < 0) {
        _DkRaiseFailure(-ret);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    LEAVE_PAL_CALL_RETURN(PAL_TRUE);
}

/* Wait for user-specified events of handles in the handle array. The wait can be timed out, unless
 * NO_TIMEOUT is given in the timeout_us argument. Returns PAL_TRUE if waiting was successful. */
PAL_BOL DkStreamsWaitEvents(PAL_NUM count, PAL_HANDLE* handle_array, PAL_FLG* events,
                            PAL_FLG* ret_events, PAL_NUM timeout_us) {
    ENTER_PAL_CALL(DkStreamsWaitEvents);

    if (!count || !handle_array || !events || !ret_events) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    for (PAL_NUM i = 0; i < count; i++) {
        if (UNKNOWN_HANDLE(handle_array[i])) {
            _DkRaiseFailure(PAL_ERROR_INVAL);
            LEAVE_PAL_CALL_RETURN(PAL_FALSE);
        }
    }

    int ret = _DkStreamsWaitEvents(count, handle_array, events, ret_events, timeout_us);
    if (ret < 0) {
        _DkRaiseFailure(-ret);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    LEAVE_PAL_CALL_RETURN(PAL_TRUE);
}
