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
 * db_object.c
 *
 * This file contains APIs for closing or polling PAL handles.
 */

#include "pal_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_error.h"
#include "pal_debug.h"
#include "api.h"
#include "atomic.h"

/* Deprecated DkObjectReference. */

int _DkObjectClose (PAL_HANDLE objectHandle)
{
    const struct handle_ops * ops = HANDLE_OPS(objectHandle);
    int ret = 0;

    /* if the operation 'close' is defined, call the function. */
    if (ops && ops->close)
        ret = ops->close(objectHandle);

    /*
     * Chia-Che 12/7/2017:
     *   _DkObjectClose will free the object, unless the handle has
     *   a 'close' operation, and the operation returns a non-zero value
     *   (e.g., 1 for skipping free() or -ERRNO).
     */
    if (!ret)
        free(objectHandle);

    return ret;
}

/* PAL call DkObjectClose: Close the given object handle. */
void DkObjectClose (PAL_HANDLE objectHandle)
{
    ENTER_PAL_CALL(DkObjectClose);

    if (!objectHandle || UNKNOWN_HANDLE(objectHandle)) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL();
    }

    UNTRACE_HEAP(objectHandle);

    int ret = _DkObjectClose(objectHandle);

    if (ret < 0)
        _DkRaiseFailure(-ret);

    LEAVE_PAL_CALL();
}

/* PAL call DkObjectsWaitAny: wait for any of the handles in the handle array.
   The wait can be timed out, unless NO_TIMEOUT is given for the timeout
   argument. */
PAL_HANDLE
DkObjectsWaitAny (PAL_NUM count, PAL_HANDLE * handleArray, PAL_NUM timeout)
{
    ENTER_PAL_CALL(DkObjectsWaitAny);

    if (!count || !handleArray) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL_RETURN(NULL);
    }

    for (int i = 0 ; i < count ; i++)
        // We modify the caller's handleArray?
        if (handleArray[i] && UNKNOWN_HANDLE(handleArray[i]))
            handleArray[i] = NULL;

    PAL_HANDLE polled = NULL;

    int ret = _DkObjectsWaitAny (count, handleArray,
                                 timeout == NO_TIMEOUT ? -1 : timeout,
                                 &polled);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        polled = NULL;
    }

    LEAVE_PAL_CALL_RETURN(polled);
}
