/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs to set up handlers of exceptions issued by the host, and the methods to
 * pass the exceptions to the upcalls.
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
    /* Interrupt  */ NULL,
};
