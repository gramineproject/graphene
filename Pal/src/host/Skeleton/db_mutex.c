/* Copyright (C) 2014 Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * db_mutex.c
 */

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

struct handle_ops mutex_ops = {
    .wait = &mutex_wait,
};
