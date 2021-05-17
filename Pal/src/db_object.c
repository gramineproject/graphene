/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs for closing or polling PAL handles.
 */

#include "api.h"
#include "atomic.h"
#include "pal.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"

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

/*
 * TODO: whole LibOS assumes this never returns errors. We need to either make `_DkObjectClose`
 * never fail (from a quick look at the code, seems like it cannot return errors in practice) or
 * make this return an `int` and handle errors in all call sites (hard to do; in most places we
 * cannot handle them in a meaningful way).
 */
/* PAL call DkObjectClose: Close the given object handle. */
void DkObjectClose(PAL_HANDLE objectHandle) {
    assert(objectHandle);

    _DkObjectClose(objectHandle);
}

/* Wait for user-specified events of handles in the handle array. The wait can be timed out, unless
 * NO_TIMEOUT is given in the timeout_us argument. Returns `0` if waiting was successful, negative
 * error code otherwise. */
int DkStreamsWaitEvents(PAL_NUM count, PAL_HANDLE* handle_array, PAL_FLG* events,
                        PAL_FLG* ret_events, PAL_NUM timeout_us) {
    for (PAL_NUM i = 0; i < count; i++) {
        if (UNKNOWN_HANDLE(handle_array[i])) {
            return -PAL_ERROR_INVAL;
        }
    }

    return _DkStreamsWaitEvents(count, handle_array, events, ret_events, timeout_us);
}
