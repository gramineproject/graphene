/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains the main function of the PAL loader, which loads and processes environment,
 * arguments and manifest.
 */

#include "api.h"
#include "pal.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"

/* must implement "pal_start", and call "pal_main" inside */
void pal_start(void);

void _DkGetAvailableUserAddressRange(PAL_PTR* start, PAL_PTR* end) {
    /* needs to be implemented */
}

int _DkGetCPUInfo(PAL_CPU_INFO* ci) {
    /* needs to be implemented */
    return 0;
}

int _DkGetTopologyInfo(PAL_TOPO_INFO* topo_info) {
    return 0;
}
