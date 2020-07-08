#include "api.h"

/* Copyright © 2005-2014 Rich Felker, et al. */

/* Permission is hereby granted, free of charge, to any person obtaining */
/* a copy of this software and associated documentation files (the */
/* "Software"), to deal in the Software without restriction, including */
/* without limitation the rights to use, copy, modify, merge, publish, */
/* distribute, sublicense, and/or sell copies of the Software, and to */
/* permit persons to whom the Software is furnished to do so, subject to */
/* the following conditions: */

/* The above copyright notice and this permission notice shall be */
/* included in all copies or substantial portions of the Software. */

/* heavily based on musl 1.1.15/1.1.24 */

void* memcpy(void* restrict dst, const void* restrict src, size_t n) {
    char* d = dst;
#if defined(__x86_64__)
    /* "Beginning with processors based on Intel microarchitecture code name Ivy Bridge, REP string
     * operation using MOVSB and STOSB can provide both flexible and high-performance REP string
     * operations for software in common situations like memory copy and set operations" (c)
     * Intel 64 and IA-32 Architectures Optimization Reference Manual.
     *
     * memcpy() is heavily used in Linux-SGX PAL to copy data in/out of SGX enclave. Experiments
     * with Redis 5.0 show perf improvement of using "rep movsb" at 3-5% for 4KB payloads over
     * previous implementation taken from Glibc 2.23. */
    __asm__ volatile("rep movsb" : "+D" (d) : "c"(n), "S"(src) : "cc", "memory");
#else
    const char* s = src;
    for (; n; n--)
        *d++ = *s++;
#endif
    return dst;
}

void* memmove(void* dst, const void* src, size_t n) {
    char* d = dst;
    const char* s = src;

    if (d == s)
        return d;

    if (s + n <= d || d + n <= s)
        return memcpy(d, s, n);

    if (d < s) {
        for (; n; n--)
            *d++ = *s++;
    } else {
        while (n) {
            n--;
            d[n] = s[n];
        }
    }
    return dst;
}
