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
 * db_process.c
 *
 * This source file contains functions to create a child process and terminate
 * the running process. Child does not inherit any objects or memory from its
 * parent pricess. A Parent process may not modify the execution of its
 * children. It can wait for a child to exit using its handle. Also, parent and
 * child may communicate through I/O streams provided by the parent to the child
 * at creation.
 */

#include "pal_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_debug.h"
#include "pal_error.h"
#include "api.h"

PAL_HANDLE
DkProcessCreate (PAL_STR uri, PAL_FLG flags, PAL_STR * args)
{
    ENTER_PAL_CALL(DkProcessCreate);

    /* DEP 3/22/17: There seems to be a default semantics that 
     * a NULL URI should replicate the parent. I think we may want
     * this to become an error in the future, but keep the behavior
     * for now, and make it consistent across hosts. */
    if (!uri)
        uri = pal_control.executable;

    log_stream(uri);

    PAL_HANDLE handle = NULL;
    int ret = _DkProcessCreate(&handle, uri, flags, args);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        handle = NULL;
    }

    TRACE_HEAP(handle);
    LEAVE_PAL_CALL_RETURN(handle);
}

void DkProcessExit (PAL_NUM exitcode)
{
    ENTER_PAL_CALL(DkProcessExit);
    _DkProcessExit(exitcode);
    _DkRaiseFailure(PAL_ERROR_NOTKILLABLE);
    LEAVE_PAL_CALL();
}

PAL_BOL DkProcessSandboxCreate (PAL_STR manifest, PAL_FLG flags)
{
    ENTER_PAL_CALL(DkProcessSandboxCreate);

    int ret = _DkProcessSandboxCreate(manifest, flags);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    LEAVE_PAL_CALL_RETURN(PAL_TRUE);
}
