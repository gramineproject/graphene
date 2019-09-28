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
 * db_signal.c
 *
 * This file contains APIs to set up handlers of exceptions issued by the
 * host, and the methods to pass the exceptions to the upcalls.
 */

#include "api.h"
#include "pal.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"

typedef void (*PAL_UPCALL)(PAL_PTR, PAL_NUM, PAL_CONTEXT*);

int (*_DkExceptionHandlers[PAL_EVENT_NUM_BOUND])(int, PAL_UPCALL, int) = {
    /* reserved   */ NULL,
    /* DivZero    */ NULL,
    /* MemFault   */ NULL,
    /* Illegal    */ NULL,
    /* Quit       */ NULL,
    /* Suspend    */ NULL,
    /* Resume     */ NULL,
    /* Failure    */ NULL,
};

void _DkRaiseFailure(int error) {
    /* needs to be implemented */
}

void _DkExceptionReturn(void* event) {
    /* needs to be implemented */
}
