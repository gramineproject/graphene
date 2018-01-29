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
#include "list.h"
#include "pal_debug.h"

#define INIT_EVENT_HANDLER      { .lock = LOCK_INIT }

struct pal_event_handler {
    PAL_LOCK lock;
    PAL_EVENT_HANDLER upcall;
};

struct pal_event_handler handlers[] = {
        [PAL_EVENT_DIVZERO]     = INIT_EVENT_HANDLER,
        [PAL_EVENT_MEMFAULT]    = INIT_EVENT_HANDLER,
        [PAL_EVENT_ILLEGAL]     = INIT_EVENT_HANDLER,
        [PAL_EVENT_QUIT]        = INIT_EVENT_HANDLER,
        [PAL_EVENT_SUSPEND]     = INIT_EVENT_HANDLER,
        [PAL_EVENT_RESUME]      = INIT_EVENT_HANDLER,
        [PAL_EVENT_FAILURE]     = INIT_EVENT_HANDLER,
    };

PAL_EVENT_HANDLER _DkGetExceptionHandler (PAL_NUM event)
{
    struct pal_event_handler * eh = &handlers[event];

    _DkInternalLock(&eh->lock);
    PAL_EVENT_HANDLER upcall = eh->upcall;
    _DkInternalUnlock(&eh->lock);

    return upcall;
}

PAL_BOL
DkSetExceptionHandler (PAL_EVENT_HANDLER handler, PAL_NUM event, PAL_FLG flags)
{
    ENTER_PAL_CALL(DkSetExceptionHandler);

    if (!handler || event == 0 ||
        event > sizeof(handlers) / sizeof(handlers[0])) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    struct pal_event_handler * eh = &handlers[event];

    _DkInternalLock(&eh->lock);
    eh->upcall = handler;
    _DkInternalUnlock(&eh->lock);

    LEAVE_PAL_CALL_RETURN(PAL_TRUE);
}

void DkExceptionReturn (PAL_PTR event)
{
    _DkExceptionReturn(event);
}

/* This does not return */
void __abort(void) {
    _DkProcessExit(1);
}

void warn (const char *format, ...)
{ 
    va_list args;
    va_start (args, format);
    vprintf(format, &args);
    va_end (args);
}

