/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2014 OSCAR lab, Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * db_semaphore.c
 *
 * This file contains APIs that provides operations of semaphores.
 */

#include "pal_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_error.h"
#include "api.h"

PAL_HANDLE
DkSemaphoreCreate (PAL_NUM initialCount, PAL_NUM maxCount)
{
    ENTER_PAL_CALL(DkSemaphoreCreate);

    PAL_HANDLE handle = NULL;
    int ret = _DkSemaphoreCreate(&handle, initialCount, maxCount);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        handle = NULL;
    }

    TRACE_HEAP(handle);
    LEAVE_PAL_CALL_RETURN(handle);
}

/* DkSemaphoreDestroy deprecated, replaced by DkObjectClose */

void DkSemaphoreRelease (PAL_HANDLE handle, PAL_NUM count)
{
    ENTER_PAL_CALL(DkSemaphoreRelease);

    if (!handle ||
        !IS_HANDLE_TYPE(handle, semaphore)) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL();
    }

    _DkSemaphoreRelease (handle, count);
    LEAVE_PAL_CALL();
}

static int sem_wait (PAL_HANDLE handle, uint64_t timeout)
{
    return _DkSemaphoreAcquireTimeout(handle, 1, timeout);
}

struct handle_ops sem_ops = {
        .wait               = &sem_wait,
    };
