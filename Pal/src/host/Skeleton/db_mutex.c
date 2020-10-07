/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#include "api.h"
#include "pal.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"

int _DkMutexCreate(PAL_HANDLE* handle, int initialCount) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkMutexLockTimeout(struct mutex_handle* m, int64_t timeout_us) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkMutexLock(struct mutex_handle* m) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkMutexAcquireTimeout(PAL_HANDLE handle, int64_t timeout_us) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkMutexUnlock(struct mutex_handle* m) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

void _DkMutexRelease(PAL_HANDLE handle) {
    /* Not implemented yet */
}

static int mutex_wait(PAL_HANDLE handle, int64_t timeout_us) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

struct handle_ops g_mutex_ops = {
    .wait = &mutex_wait,
};
