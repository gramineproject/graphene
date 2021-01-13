/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs to set up handlers of exceptions issued by the host, and the methods to
 * pass the exceptions to the upcalls.
 */

#include <errno.h>

#include "api.h"
#include "list.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"

PAL_EVENT_HANDLER g_handlers[PAL_EVENT_NUM_BOUND] = {0};

PAL_EVENT_HANDLER _DkGetExceptionHandler(PAL_NUM event) {
    return __atomic_load_n(&g_handlers[event], __ATOMIC_ACQUIRE);
}

PAL_BOL
DkSetExceptionHandler(PAL_EVENT_HANDLER handler, PAL_NUM event) {
    ENTER_PAL_CALL(DkSetExceptionHandler);

    if (!handler || event == 0 || event >= ARRAY_SIZE(g_handlers)) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    __atomic_store_n(&g_handlers[event], handler, __ATOMIC_RELEASE);
    LEAVE_PAL_CALL_RETURN(PAL_TRUE);
}

/* This does not return */
noreturn void __abort(void) {
    _DkProcessExit(ENOTRECOVERABLE);
}

void warn(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}
