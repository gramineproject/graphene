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
DkSetExceptionHandler (void (*handler) (PAL_PTR event, PAL_NUM arg,
                                        PAL_CONTEXT * context),
                       PAL_NUM event, PAL_FLG flags)
{
    if (!handler || event <= 0 || event > PAL_EVENT_NUM_BOUND) {
        notify_failure(PAL_ERROR_INVAL);
        return PAL_FALSE;
    }

    int ret = _DkExceptionHandlers[event](event, handler, flags);

    if (ret < 0) {
        notify_failure(-ret);
        return PAL_FALSE;
    }

    return PAL_TRUE;
}

void DkExceptionReturn (PAL_PTR event)
{
    _DkExceptionReturn(event);
}
