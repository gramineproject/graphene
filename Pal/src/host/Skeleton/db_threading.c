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

/* _DkThreadCreate for internal use. Create an internal thread
   inside the current process. The arguments callback and param
   specify the starting function and parameters */
int _DkThreadCreate (PAL_HANDLE * handle, int (*callback) (void *),
                     const void * param, int flags)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkThreadDelayExecution (unsigned long * duration)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* PAL call DkThreadYieldExecution. Yield the execution
   of the current thread. */
void _DkThreadYieldExecution (void)
{
    /* need to be implemented */
}

/* _DkThreadExit for internal use: Thread exiting */
void _DkThreadExit (void)
{
    /* need to be implemented */
}

int _DkThreadResume (PAL_HANDLE threadHandle)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

struct handle_ops thread_ops = {
    /* nothing */
};
