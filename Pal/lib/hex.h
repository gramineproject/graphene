/* Copyright (C) 2014 OSCAR lab, Stony Brook University
   2017 University of North Carolina at Chapel Hill
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

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
    static char * ch = "0123456789abcdef";
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
