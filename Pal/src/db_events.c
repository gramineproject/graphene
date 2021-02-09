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
    PAL_HANDLE handle = NULL;
    int ret = _DkEventCreate(&handle, initialState, true);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        handle = NULL;
    }

    return handle;
}

PAL_HANDLE DkSynchronizationEventCreate(PAL_BOL initialState) {
    PAL_HANDLE handle = NULL;
    int ret = _DkEventCreate(&handle, initialState, false);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        handle = NULL;
    }

    return handle;
}

/* DkEventDestroy deprecated, replaced by DkObjectClose */

void DkEventSet(PAL_HANDLE handle) {
    if (!handle || !IS_HANDLE_TYPE(handle, event)) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        return;
    }

    int ret = _DkEventSet(handle, -1);

    if (ret < 0)
        _DkRaiseFailure(-ret);
}

void DkEventClear(PAL_HANDLE handle) {
    if (!handle || !IS_HANDLE_TYPE(handle, event)) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        return;
    }

    int ret = _DkEventClear(handle);

    if (ret < 0)
        _DkRaiseFailure(-ret);
}
