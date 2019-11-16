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

#include "api.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"

PAL_HANDLE
DkProcessCreate(PAL_STR uri, PAL_STR* args) {
    ENTER_PAL_CALL(DkProcessCreate);

    /* DEP 3/22/17: There seems to be a default semantics that
     * a NULL URI should replicate the parent. I think we may want
     * this to become an error in the future, but keep the behavior
     * for now, and make it consistent across hosts. */
    if (!uri)
        uri = pal_control.executable;

    log_stream(uri);

    PAL_HANDLE handle = NULL;
    int ret           = _DkProcessCreate(&handle, uri, args);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        handle = NULL;
    }

    LEAVE_PAL_CALL_RETURN(handle);
}

noreturn void DkProcessExit(PAL_NUM exitcode) {
    ENTER_PAL_CALL(DkProcessExit);
    _DkProcessExit(exitcode);
    _DkRaiseFailure(PAL_ERROR_NOTKILLABLE);
    while (true)
        /* nothing */;
    LEAVE_PAL_CALL();
}
