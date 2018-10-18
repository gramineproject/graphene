/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

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
 * db_event.c
 *
 * This file contains implementation of Drawbridge event synchronization APIs.
 */

#include "pal_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_error.h"
#include "api.h"

int _DkEventCreate (PAL_HANDLE * event, bool initialState, bool isnotification)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

void _DkEventDestroy (PAL_HANDLE handle)
{
    /* need to be implemented */
}

int _DkEventSet (PAL_HANDLE event, int wakeup)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkEventWaitTimeout (PAL_HANDLE event, uint64_t timeout)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkEventWait (PAL_HANDLE event)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkEventClear (PAL_HANDLE event)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}
