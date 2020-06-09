/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 OSCAR lab, Stony Brook University
 * 2017 University of North Carolina at Chapel Hill
 */

#ifndef HEX_H
#define HEX_H

#include <api.h>
#include <assert.h>
#include <stddef.h>
#include <stdint.h>

/* This function is a helper for debug printing.
 * It accepts a pointer to a numerical value, and
 * formats it as a hex string, for printing.
 * size is the number of bytes pointed to by hex.
 * str is the caller-provided buffer, len is the length of the buffer.
 * The len must be at least (size * 2)+1.
 *
 * Note that it does not normalize for endianness, and pads to the
 * size the compiler things the string is.
 */
static inline __attribute__((always_inline))
char * __bytes2hexstr(void * hex, size_t size, char *str, size_t len)
{
    static const char* ch = "0123456789abcdef";
    __UNUSED(len);
    assert(len >= size * 2 + 1);

    for (size_t i = 0 ; i < size ; i++) {
        unsigned char h = ((unsigned char *) hex)[i];
        str[i * 2] = ch[h / 16];
        str[i * 2 + 1] = ch[h % 16];
    }

    str[size * 2] = 0;
    return str;
}

#define IS_INDEXABLE(arg) (sizeof((arg)[0]))
#define IS_ARRAY(arg) (IS_INDEXABLE(arg) > 0 && (((void *) &(arg)) == ((void *) (arg))))

static inline __attribute__((always_inline))
int8_t hex2dec(char c) {
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    else if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    else if (c >= '0' && c <= '9')
        return c - '0';
    else
        return -1;
}

/*
 * BYTES2HEXSTR converts an array into a hexadecimal string and fills into a
 * given buffer. The buffer size is given as an extra argument.
 */
#define BYTES2HEXSTR(array, str, len) ({                        \
    static_assert(IS_ARRAY(array), "`array` must be an array"); \
    __bytes2hexstr((array), sizeof(array), str, len);})

/*
 * ALLOCA_BYTES2HEXSTR uses __alloca to allocate a buffer on the current frame
 * and then fills the hexadecimal string into the buffer.
 * This buffer can only be used within the caller frame (function).
 */
#define ALLOCA_BYTES2HEXSTR(array) \
    (BYTES2HEXSTR(array, __alloca(sizeof(array) * 2 + 1), sizeof(array) * 2 + 1))

#endif // HEX_H
