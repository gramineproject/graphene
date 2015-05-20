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
 * db_exception.c
 *
 * This file contains APIs to set up handlers of exceptions issued by the
 * host, and the methods to pass the exceptions to the upcalls.
 */

#include "pal_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_error.h"
#include "api.h"
#include "linux_list.h"

PAL_BOL
DkSetExceptionHandler (void (*handler) (PAL_PTR, PAL_NUM, PAL_CONTEXT *),
                       PAL_NUM event, PAL_FLG flags)
{
    store_frame(SetExceptionHandler);

    if (!handler || event <= 0 || event > PAL_EVENT_NUM_BOUND)
        leave_frame(PAL_FALSE, PAL_ERROR_INVAL);

    int ret = _DkExceptionHandlers[event](event, handler, flags);

    if (ret < 0)
        leave_frame(PAL_FALSE, -ret);

    leave_frame(PAL_TRUE, 0);
}

void DkExceptionReturn (PAL_PTR event)
{
    _DkExceptionReturn(event);
}

unsigned long _DkHandleCompatibilityException (unsigned long syscallno,
                                               unsigned long args[6])
{
    printf("compatibility support: detected an unintercepted system call\n");

    if (!pal_state.syscall_sym_addr)
        _DkProcessExit(-1);

    unsigned long ret;

    asm volatile ("movq %6, %%r10\r\n"
                  "movq %7, %%r8\r\n"
                  "movq %8, %%r9\r\n"
                  "callq *%1\r\n"
                  "movq %%rax, %0\r\n"
                  : "=a" (ret)
                  : "r"(pal_state.syscall_sym_addr),
                    "a" (syscallno),
                    "D" (args[0]),
                    "S" (args[1]),
                    "d" (args[2]),
                    "r" (args[3]),
                    "r" (args[4]),
                    "r" (args[5])
                  : "memory", "r10", "r8", "r9");

    return ret;
}
