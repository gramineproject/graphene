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
 * db_threading.c
 *
 * This file contain APIs to create, exit and yield a thread.
 */

#include "pal_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_error.h"
#include "pal_debug.h"
#include "api.h"

/* PAL call DkThreadCreate: create a thread inside the current
   process */
PAL_HANDLE
DkThreadCreate (PAL_PTR addr, PAL_PTR param, PAL_FLG flags)
{
    store_frame(ThreadCreate);

    PAL_HANDLE handle = NULL;
    int ret = _DkThreadCreate (&handle, (int (*)(void *)) addr,
                               param, flags);

    if (ret < 0)
        leave_frame(NULL, -ret);

    leave_frame(handle, 0);
}

/* PAL call DkThreadDelayExecution. Delay the current thread
   (sleep) for the given duration */
PAL_NUM
DkThreadDelayExecution (PAL_NUM duration)
{
    store_frame(ThreadDelayExecution);

    unsigned long dur = duration;
    int ret = _DkThreadDelayExecution(&dur);

    if (ret < 0)
        leave_frame(dur, PAL_ERROR_INTERRUPTED);

    leave_frame(duration, 0);
}

/* PAL call DkThreadYieldExecution. Yield the execution
   of the current thread. */
void DkThreadYieldExecution (void)
{
    _DkThreadYieldExecution();
}

/* PAL call DkThreadExit: simply exit the current thread
   no matter what */
void DkThreadExit (void)
{
    store_frame(ThreadExit);
    _DkThreadExit();
    leave_frame(, PAL_ERROR_NOTKILLABLE);
}

/* PAL call DkThreadResume: resume the execution of a thread
   which is delayed before */
PAL_BOL DkThreadResume (PAL_HANDLE threadHandle)
{
    store_frame(ThreadResume);

    if (!threadHandle || !IS_HANDLE_TYPE(threadHandle, thread))
        leave_frame(PAL_FALSE, PAL_ERROR_INVAL);

    int ret = _DkThreadResume(threadHandle);

    if (ret < 0)
        leave_frame(PAL_FALSE, PAL_ERROR_DENIED);

    leave_frame(PAL_TRUE, 0);
}
