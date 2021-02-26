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

int DkNotificationEventCreate(PAL_BOL initialState, PAL_HANDLE* handle) {
    *handle = NULL;
    return _DkEventCreate(handle, initialState, true);
}

int DkSynchronizationEventCreate(PAL_BOL initialState, PAL_HANDLE* handle) {
    *handle = NULL;
    return _DkEventCreate(handle, initialState, false);
}

int DkEventSet(PAL_HANDLE handle) {
    if (!handle || !IS_HANDLE_TYPE(handle, event)) {
        return -PAL_ERROR_INVAL;
    }

    return _DkEventSet(handle, -1);
}

int DkEventClear(PAL_HANDLE handle) {
    if (!handle || !IS_HANDLE_TYPE(handle, event)) {
        return -PAL_ERROR_INVAL;
    }

    return _DkEventClear(handle);
}
