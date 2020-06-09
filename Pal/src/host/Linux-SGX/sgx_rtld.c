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

#include <api.h>
#include <pal_internal.h>

#include "sgx_internal.h"

__asm__(".pushsection \".debug_gdb_scripts\", \"MS\",@progbits,1\r\n"
        ".byte 1\r\n"
        ".asciz \"" PAL_FILE("host/Linux-SGX/debugger/pal-gdb.py") "\"\r\n"
        ".popsection\r\n");

/* This function is hooked by our gdb integration script and should be
 * left as is. */
void load_gdb_command(const char* command) {
    __UNUSED(command);
}
