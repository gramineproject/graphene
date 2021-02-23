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

int DkProcessCreate(PAL_STR exec_uri, PAL_STR* args, PAL_HANDLE* handle) {
    assert(exec_uri);

    *handle = NULL;
    return _DkProcessCreate(handle, exec_uri, args);
}

noreturn void DkProcessExit(PAL_NUM exitcode) {
    _DkProcessExit(exitcode);
    die_or_inf_loop();
}
