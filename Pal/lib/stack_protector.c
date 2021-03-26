/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include "assert.h"

noreturn void __stack_chk_fail(void) {
    warn("Stack protector: Graphene internal stack corruption detected\n");
    __abort();
}
