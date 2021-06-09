/* Copyright (C) 1991, 1997 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA. */

/* Copyright (C) 2021 Intel Corporation
 *                    Vijay Dhanraj <vijay.dhanraj@intel.com>
 */

#include <limits.h>
#include <stdint.h>

#include "api.h"

long strtol(const char* s, char** endptr, int base) {
    int neg  = 0;
    long val = 0;

    // gobble initial whitespace
    while (*s == ' ' || *s == '\t') {
        s++;
    }

    // plus/minus sign
    if (*s == '+')
        s++;
    else if (*s == '-')
        s++, neg = 1;

    // hex or octal base prefix
    if ((base == 0 || base == 16) && (s[0] == '0' && s[1] == 'x'))
        s += 2, base = 16;
    else if (base == 0 && s[0] == '0')
        s++, base = 8;
    else if (base == 0)
        base = 10;

    // digits
    while (1) {
        int dig;

        if (*s >= '0' && *s <= '9')
            dig = *s - '0';
        else if (*s >= 'a' && *s <= 'z')
            dig = *s - 'a' + 10;
        else if (*s >= 'A' && *s <= 'Z')
            dig = *s - 'A' + 10;
        else
            break;
        if (dig >= base)
            break;
        s++, val = (val * base) + dig;
        // we don't properly detect overflow!
    }

    if (endptr)
        *endptr = (char*)s;
    return (neg ? -val : val);
}

int str_to_ulong(const char* str, unsigned int base, unsigned long* out_value,
                 const char** out_end) {
    if (base == 16 && str[0] == '0' && str[1] == 'x')
        str += 2;

    unsigned long value = 0;
    const char* s = str;
    while (*s != '\0') {
        unsigned int digit;
        if ('0' <= *s && *s <= '9') {
            digit = *s - '0';
        } else if ('a' <= *s && *s <= 'z') {
            digit = *s - 'a' + 10;
        } else if ('A' <= *s && *s <= 'Z') {
            digit = *s - 'A' + 10;
        } else {
            break;
        }
        if (digit >= base)
            break;

        if (__builtin_mul_overflow(value, base, &value))
            return -1;

        if (__builtin_add_overflow(value, digit, &value))
            return -1;

        s++;
    }

    if (s == str)
        return -1;

    *out_value = value;
    *out_end = s;
    return 0;
}

#ifdef __LP64__
/* long int == long long int on targets with data model LP64 */
long long strtoll(const char* s, char** endptr, int base) {
    return (long long)strtol(s, endptr, base);
}
#else
#error "Unsupported architecture (only support data model LP64)"
#endif

/* Convert a string to an int.  */
int atoi(const char* nptr) {
    return (int)strtol(nptr, (char**)NULL, 10);
}

/* Convert a string to an long int.  */
long int atol(const char* nptr) {
    return strtol(nptr, (char**)NULL, 10);
}

/* Parse a size (number with optional "G"/"M"/"K" suffix) into an unsigned long. Returns -1 if
 * cannot parse the size, e.g. if the suffix is wrong. */
int64_t parse_size_str(const char* str) {
    char* endptr = NULL;
    long size = strtol(str, &endptr, 0);

    if (endptr[0] == 'G' || endptr[0] == 'g')
        size *= 1024 * 1024 * 1024;
    else if (endptr[0] == 'M' || endptr[0] == 'm')
        size *= 1024 * 1024;
    else if (endptr[0] == 'K' || endptr[0] == 'k')
        size *= 1024;
    else if (endptr[0] != '\0')
        size = -1; /* wrong suffix */

    return size;
}
