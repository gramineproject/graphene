/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * db_rtld.c
 *
 * This file contains utilities to load ELF binaries into the memory
 * and link them against each other.
 * The source code in this file is imported and modified from the GNU C
 * Library.
 */

#include <dlfcn.h>
#include <elf/elf.h>
#include <sysdeps/generic/ldsodefs.h>

#include "api.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_rtld.h"

void _DkDebugAddMap(struct link_map* map) {}

void _DkDebugDelMap(struct link_map* map) {}
