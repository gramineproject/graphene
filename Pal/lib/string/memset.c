/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Invisible Things Lab
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

#include <stdint.h>

#include "api.h"

void* memset(void* dest, int ch, size_t count) {
    char* d = dest;
#if defined(__x86_64__)
    /* "Beginning with processors based on Intel microarchitecture code name Ivy Bridge, REP string
     * operation using MOVSB and STOSB can provide both flexible and high-performance REP string
     * operations for software in common situations like memory copy and set operations"
     * Intel 64 and IA-32 Architectures Optimization Reference Manual
     */
    __asm__ volatile("rep stosb" : "+&D"(d), "+&c"(count) : "a"((uint8_t)ch) : "cc", "memory");
#else
    while (count--)
        *d++ = ch;
#endif
    return dest;
}
