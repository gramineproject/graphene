/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

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

    PAL_HANDLE handle = NULL;
    int ret = _DkProcessCreate(&handle, uri, args);

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
