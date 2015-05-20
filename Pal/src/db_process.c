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
    store_frame(ProcessCreate);

    PAL_HANDLE handle = NULL;
    int ret = _DkProcessCreate(&handle, uri, flags, args);

    if (ret < 0)
        leave_frame(NULL, -ret);

    leave_frame(handle, 0);
}

void DkProcessExit (PAL_NUM exitcode)
{
    store_frame(ProcessExit);
    _DkProcessExit(exitcode);
    leave_frame(, PAL_ERROR_NOTKILLABLE);
}

PAL_BOL DkProcessSandboxCreate (PAL_STR manifest, PAL_FLG flags)
{
    store_frame(ProcessSandboxCreate);

    int ret = _DkProcessSandboxCreate(manifest, flags);

    if (ret < 0)
        leave_frame(PAL_FALSE, -ret);

    leave_frame(PAL_TRUE, 0);
}
