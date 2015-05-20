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
 * db_event.c
 *
 * This file contains implementation of Drawbridge event synchronization APIs.
 */

#include "pal_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_error.h"
#include "api.h"

PAL_HANDLE DkNotificationEventCreate (PAL_BOL initialState)
{
    store_frame(NotificationEventCreate);

    PAL_HANDLE handle = NULL;
    int ret = _DkEventCreate(&handle, initialState, true);

    if (ret < 0)
        leave_frame(NULL, -ret);

    leave_frame(handle, 0);
}

PAL_HANDLE DkSynchronizationEventCreate (PAL_BOL initialState)
{
    store_frame(SynchronizationEventCreate);

    PAL_HANDLE handle = NULL;
    int ret = _DkEventCreate(&handle, initialState, false);

    if (ret < 0)
        leave_frame(NULL, -ret);

    leave_frame(handle, 0);
}

void DkEventDestroy (PAL_HANDLE handle)
{
    store_frame(EventDestroy);

    if (!handle || !IS_HANDLE_TYPE(handle, event))
        leave_frame(, PAL_ERROR_INVAL);

    _DkEventDestroy(handle);
    leave_frame(, 0);
}

void DkEventSet (PAL_HANDLE handle)
{
    store_frame(EventSet);

    if (!handle || !IS_HANDLE_TYPE(handle, event))
        leave_frame(, PAL_ERROR_INVAL);

    int ret = _DkEventSet (handle);

    if (ret < 0)
        leave_frame(, -ret);

    leave_frame(, 0);
}

void DkEventWait (PAL_HANDLE handle)
{
    store_frame(EventWait);

    if (!handle || !IS_HANDLE_TYPE(handle, event))
        leave_frame(, PAL_ERROR_INVAL);

    int ret = _DkEventWait(handle);

    if (ret < 0)
        leave_frame(, -ret);

    leave_frame(, 0);
}

void DkEventClear (PAL_HANDLE handle)
{
    store_frame(EventClear);

    if (!handle || !IS_HANDLE_TYPE(handle, event))
        leave_frame(, PAL_ERROR_INVAL);

    int ret = _DkEventClear(handle);

    if (ret < 0)
        leave_frame(, -ret);

    leave_frame(, 0);
}

static int event_close (PAL_HANDLE handle)
{
    return _DkEventClear(handle);
}

static int event_wait (PAL_HANDLE handle, int timeout)
{
    return timeout >=0 ? _DkEventWaitTimeout(handle, timeout) :
           _DkEventWait(handle);
}

struct handle_ops event_ops = {
        .close              = &event_close,
        .wait               = &event_wait,
    };
