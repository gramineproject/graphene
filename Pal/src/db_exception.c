/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * db_exception.c
 *
 * This file contains APIs to set up handlers of exceptions issued by the
 * host, and the methods to pass the exceptions to the upcalls.
 */

#include <errno.h>

#include "api.h"
#include "list.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"

#define INIT_EVENT_HANDLER { .lock = LOCK_INIT, .upcall = NULL }

struct pal_event_handler {
    PAL_LOCK lock;
    PAL_EVENT_HANDLER upcall;
};

struct pal_event_handler handlers[] = {
    [0]                          = INIT_EVENT_HANDLER,
    [PAL_EVENT_ARITHMETIC_ERROR] = INIT_EVENT_HANDLER,
    [PAL_EVENT_MEMFAULT]         = INIT_EVENT_HANDLER,
    [PAL_EVENT_ILLEGAL]          = INIT_EVENT_HANDLER,
    [PAL_EVENT_QUIT]             = INIT_EVENT_HANDLER,
    [PAL_EVENT_SUSPEND]          = INIT_EVENT_HANDLER,
    [PAL_EVENT_RESUME]           = INIT_EVENT_HANDLER,
    [PAL_EVENT_FAILURE]          = INIT_EVENT_HANDLER,
    [PAL_EVENT_PIPE]             = INIT_EVENT_HANDLER,
};

PAL_EVENT_HANDLER _DkGetExceptionHandler(PAL_NUM event) {
    struct pal_event_handler* eh = &handlers[event];

    _DkInternalLock(&eh->lock);
    PAL_EVENT_HANDLER upcall = eh->upcall;
    _DkInternalUnlock(&eh->lock);

    return upcall;
}

PAL_BOL
DkSetExceptionHandler(PAL_EVENT_HANDLER handler, PAL_NUM event) {
    ENTER_PAL_CALL(DkSetExceptionHandler);

    if (!handler || event == 0 || event >= ARRAY_SIZE(handlers)) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    struct pal_event_handler* eh = &handlers[event];

    _DkInternalLock(&eh->lock);
    eh->upcall = handler;
    _DkInternalUnlock(&eh->lock);

    LEAVE_PAL_CALL_RETURN(PAL_TRUE);
}

void DkExceptionReturn(PAL_PTR event) {
    _DkExceptionReturn(event);
}

/* This does not return */
noreturn void __abort(void) {
    _DkProcessExit(-ENOTRECOVERABLE);
}

void warn(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}
