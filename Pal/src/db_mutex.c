/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs that provides operations of mutexes.
 */

#include "api.h"
#include "pal.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"

PAL_HANDLE
DkMutexCreate(PAL_NUM initialCount) {
    PAL_HANDLE handle = NULL;
    int ret = _DkMutexCreate(&handle, initialCount);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        handle = NULL;
    }

    return handle;
}

void DkMutexRelease(PAL_HANDLE handle) {
    if (!handle || !IS_HANDLE_TYPE(handle, mutex)) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        return;
    }

    _DkMutexRelease(handle);
}
