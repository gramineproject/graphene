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
    ENTER_PAL_CALL(DkThreadCreate);

    PAL_HANDLE handle = NULL;
    int ret = _DkThreadCreate (&handle, (int (*)(void *)) addr,
                               (const void *) param, flags);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        handle = NULL;
    }

    TRACE_HEAP(handle);
    LEAVE_PAL_CALL_RETURN(handle);
}

/* PAL call DkThreadDelayExecution. Delay the current thread
   (sleep) for the given duration */
PAL_NUM
DkThreadDelayExecution (PAL_NUM duration)
{
    ENTER_PAL_CALL(DkThreadDelayExecution);

    unsigned long dur = duration;
    int ret = _DkThreadDelayExecution(&dur);

    if (ret < 0) {
        _DkRaiseFailure(PAL_ERROR_INTERRUPTED);
        duration = dur;
    }

    LEAVE_PAL_CALL_RETURN(duration);
}

/* PAL call DkThreadYieldExecution. Yield the execution
   of the current thread. */
void DkThreadYieldExecution (void)
{
    ENTER_PAL_CALL(DkThreadYieldExecution);
    _DkThreadYieldExecution();
    LEAVE_PAL_CALL();
}

/* PAL call DkThreadExit: simply exit the current thread
   no matter what */
void DkThreadExit (void)
{
    ENTER_PAL_CALL(DkThreadExit);
    _DkThreadExit();
    _DkRaiseFailure(PAL_ERROR_NOTKILLABLE);
    LEAVE_PAL_CALL();
}

/* PAL call DkThreadResume: resume the execution of a thread
   which is delayed before */
PAL_BOL DkThreadResume (PAL_HANDLE threadHandle)
{
    ENTER_PAL_CALL(DkThreadResume);

    if (!threadHandle || !IS_HANDLE_TYPE(threadHandle, thread)) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    int ret = _DkThreadResume(threadHandle);

    if (ret < 0) {
        _DkRaiseFailure(PAL_ERROR_DENIED);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    LEAVE_PAL_CALL_RETURN(PAL_TRUE);
}
