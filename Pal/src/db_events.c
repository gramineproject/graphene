/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
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
    int ret = _DkEventCreate(&handle, initialState, true);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        handle = NULL;
    }

    LEAVE_PAL_CALL_RETURN(handle);
}

PAL_HANDLE DkSynchronizationEventCreate(PAL_BOL initialState) {
    ENTER_PAL_CALL(DkSynchronizationEventCreate);

    PAL_HANDLE handle = NULL;
    int ret = _DkEventCreate(&handle, initialState, false);

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
