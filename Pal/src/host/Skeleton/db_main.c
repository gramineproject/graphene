/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * db_main.c
 *
 * This file contains the main function of the PAL loader, which loads and
 * processes environment, arguments and manifest.
 */

#include "pal_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_debug.h"
#include "pal_error.h"
#include "api.h"

/* must implement "pal_start", and call "pal_main" inside */
void pal_start (void);

unsigned long _DkGetAllocationAlignment (void)
{
    return 0;
}

void _DkGetAvailableUserAddressRange(PAL_PTR* start, PAL_PTR* end, PAL_NUM* gap) {
    /* needs to be implemented */
}

PAL_NUM _DkGetProcessId (void)
{
    return 0;
}

PAL_NUM _DkGetHostId (void)
{
    return 0;
}

int _DkGetCPUInfo (PAL_CPU_INFO * ci)
{
    /* needs to be implemented */
    return 0;
}
