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

/* The below function is used by stack protector's __stack_chk_fail(), _FORTIFY_SOURCE's *_chk()
 * functions and by assert.h's assert() defined in the common library. Thus it might be called by
 * any PAL thread. */
noreturn void pal_abort(void) {
    _DkProcessExit(ENOTRECOVERABLE);
}
