/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This source file contains functions to create a child process and terminate the running process.
 * Child does not inherit any objects or memory from its parent process. A parent process may not
 * modify the execution of its children. It can wait for a child to exit using its handle. Also,
 * parent and child may communicate through I/O streams provided by the parent to the child at
 * creation.
 */

#include "api.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"

PAL_HANDLE DkProcessCreate(PAL_STR exec_uri, PAL_STR* args) {
    ENTER_PAL_CALL(DkProcessCreate);
    assert(exec_uri);

    PAL_HANDLE handle = NULL;
    int ret = _DkProcessCreate(&handle, exec_uri, args);

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
    die_or_inf_loop();
    LEAVE_PAL_CALL();
}
