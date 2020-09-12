/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

#include "pal_debug.h"
#include "sgx_internal.h"

/* This function is hooked by our gdb integration script and should be left as is. */
__attribute__((__noinline__)) void execute_gdb_command(const char* command) {
    __UNUSED(command);
    __asm__ volatile(""); // Required in addition to __noinline__ to prevent deleting this function.
                          // See GCC docs.
}
