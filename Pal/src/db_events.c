/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include "assert.h"
#include "pal.h"
#include "pal_internal.h"

int DkEventCreate(PAL_HANDLE* handle, bool init_signaled, bool auto_clear) {
    *handle = NULL;
    return _DkEventCreate(handle, init_signaled, auto_clear);
}

void DkEventSet(PAL_HANDLE handle) {
    assert(handle && IS_HANDLE_TYPE(handle, event));
    _DkEventSet(handle);
}

void DkEventClear(PAL_HANDLE handle) {
    assert(handle && IS_HANDLE_TYPE(handle, event));
    _DkEventClear(handle);
}
