/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include "assert.h"
#include "pal.h"
#include "pal_internal.h"

int DkEventCreate(PAL_HANDLE* handle, bool init_signaled, bool auto_clear) {
    assert(current_context_is_libos());
    current_context_set_pal();

    *handle = NULL;
    int ret = _DkEventCreate(handle, init_signaled, auto_clear);

    current_context_set_libos();
    return ret;
}

void DkEventSet(PAL_HANDLE handle) {
    assert(current_context_is_libos());
    current_context_set_pal();

    assert(handle && IS_HANDLE_TYPE(handle, event));
    _DkEventSet(handle);

    current_context_set_libos();
}

void DkEventClear(PAL_HANDLE handle) {
    assert(current_context_is_libos());
    current_context_set_pal();

    assert(handle && IS_HANDLE_TYPE(handle, event));
    _DkEventClear(handle);

    current_context_set_libos();
}

int DkEventWait(PAL_HANDLE handle, uint64_t* timeout_us) {
    assert(current_context_is_libos());
    current_context_set_pal();

    assert(handle && IS_HANDLE_TYPE(handle, event));
    int ret = _DkEventWait(handle, timeout_us);

    current_context_set_libos();
    return ret;
}
