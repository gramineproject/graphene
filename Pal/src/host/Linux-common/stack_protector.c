/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation */

#include "api.h"
#include "linux_utils.h"
#include "pal_internal.h"

/* we use GCC's stack protector; when it detects corrupted stack, it calls __stack_chk_fail() */
noreturn void __stack_chk_fail(void) {
    printf("Stack protector: Graphene PAL internal stack corruption detected\n");
    _DkProcessExit(1);
}
