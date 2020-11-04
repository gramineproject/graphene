/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#ifndef _PAL_INTERNAL_ARCH_H
#define _PAL_INTERNAL_ARCH_H

#include "assert.h"

#define ARCH_PROBE_STACK(size, page_size)           \
    assert(size / page_size > 0);                   \
    __asm__ volatile(                               \
        "mov %%rsp, %%rdx\n"                        \
        "1:\n"                                      \
        "sub %0, %%rsp\n"                           \
        "orq $0, (%%rsp)\n"                         \
        "loop 1b\n"                                 \
        "mov %%rdx, %%rsp\n"                        \
        :                                           \
        : "ri"(page_size), "c"(size / page_size)    \
        : "memory", "cc", "rdx"                     \
    )

#endif // _PAL_INTERNAL_ARCH_H
