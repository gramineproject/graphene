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

int _DkEventCreate(PAL_HANDLE* event, bool initialState, bool isnotification) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkEventSet(PAL_HANDLE event, int wakeup) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkEventWaitTimeout(PAL_HANDLE event, int64_t timeout_us) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkEventClear(PAL_HANDLE event) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int event_close(PAL_HANDLE handle) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int event_wait(PAL_HANDLE handle, int64_t timeout_us) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

struct handle_ops g_event_ops = {
    .close = &event_close,
    .wait  = &event_wait,
};
