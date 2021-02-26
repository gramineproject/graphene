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

int DkMutexCreate(PAL_NUM initialCount, PAL_HANDLE* handle) {
    *handle = NULL;
    return _DkMutexCreate(handle, initialCount);
}

void DkMutexRelease(PAL_HANDLE handle) {
    assert(handle && IS_HANDLE_TYPE(handle, mutex));

    _DkMutexRelease(handle);
}
