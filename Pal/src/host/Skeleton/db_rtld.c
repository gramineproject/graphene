/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains host-specific code related to linking and reporting ELFs to debugger.
 */

#include "pal_rtld.h"

void _DkDebugMapAdd(const char* name, void* addr) {}

void _DkDebugMapRemove(void* addr) {}
