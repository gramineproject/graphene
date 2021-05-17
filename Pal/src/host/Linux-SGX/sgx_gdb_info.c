/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

#include "sgx_internal.h"

/* This function is hooked by our gdb integration script and should be left as is. */
__attribute__((__noinline__)) void update_debugger(void) {
    __asm__ volatile(""); // Required in addition to __noinline__ to prevent deleting this function.
                          // See GCC docs.
}
