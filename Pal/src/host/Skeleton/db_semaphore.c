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
 * db_semaphore.c
 *
 * This file contains APIs that provides operations of semaphores.
 */

#include "api.h"
#include "pal.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"

int _DkSemaphoreCreate(PAL_HANDLE handle, int initialCount, int maxCount) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

void _DkSemaphoreDestroy(PAL_HANDLE semaphoreHandle) {
    /* need to be implemented */
}

int _DkSemaphoreAcquire(PAL_HANDLE sem, int count) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkSemaphoreAcquireTimeout(PAL_HANDLE sem, int count, int timeout) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

void _DkSemaphoreRelease(PAL_HANDLE sem, int count) {
    /* need to be implemented */
}

int _DkSemaphoreGetCurrentCount(PAL_HANDLE sem) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}
