/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains utilities to load ELF binaries into the memory and link them against each
 * other.
 */

#include <dlfcn.h>

#include "api.h"
#include "elf/elf.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_rtld.h"
#include "sysdeps/generic/ldsodefs.h"

void _DkDebugAddMap(struct link_map* map) {}

void _DkDebugDelMap(struct link_map* map) {}
