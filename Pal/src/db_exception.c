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

void DkSetExceptionHandler(PAL_EVENT_HANDLER handler, PAL_NUM event) {
    assert(handler && event != 0 && event < ARRAY_SIZE(g_handlers));

    __atomic_store_n(&g_handlers[event], handler, __ATOMIC_RELEASE);
}

noreturn void __abort(void) {
    _DkProcessExit(ENOTRECOVERABLE);
}

// TODO: Remove this and always use log_*.
void warn(const char* format, ...) {
    va_list args;
    va_start(args, format);
    pal_vprintf(format, args);
    va_end(args);
}
