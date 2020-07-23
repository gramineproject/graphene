/* SPDX-License-Identifier: LGPL-3.0-or-later */

#include <stdint.h>

#include "api.h"

void* memcpy(void* restrict dest, const void* restrict src, size_t count) {
    char* d = dest;
#if defined(__x86_64__)
    /* "Beginning with processors based on Intel microarchitecture code name Ivy Bridge, REP string
     * operation using MOVSB and STOSB can provide both flexible and high-performance REP string
     * operations for software in common situations like memory copy and set operations" (c)
     * Intel 64 and IA-32 Architectures Optimization Reference Manual.
     *
     * memcpy() is heavily used in Linux-SGX PAL to copy data in/out of SGX enclave. Experiments
     * with Redis 5.0 show perf improvement of using "rep movsb" at 3-5% for 4KB payloads over
     * previous implementation taken from Glibc 2.23. */
    __asm__ volatile("rep movsb" : "+&D"(d), "+&c"(count) : "S"(src) : "cc", "memory");
#else
    const char* s = src;
    while (count--)
        *d++ = *s++;
#endif
    return dest;
}

void* memmove(void* dest, const void* src, size_t count) {
    char* d = dest;
    const char* s = src;

    if (d == s)
        return d;

    if (s + count <= d || d + count <= s)
        return memcpy(d, s, count);

    if (d < s) {
        while (count--)
            *d++ = *s++;
    } else {
        while (count--)
            d[count] = s[count];
    }
    return dest;
}
