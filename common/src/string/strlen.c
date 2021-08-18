/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

#include "api.h"

/* Find the length of S, but scan at most MAXLEN characters.  If no
   '\0' terminator is found in that many characters, return MAXLEN.  */
size_t strnlen(const char* str, size_t maxlen) {
    size_t len = 0;
    while (len < maxlen && *str != '\0') {
        str++;
        len++;
    }
    return len;
}

size_t strlen(const char* str) {
    size_t len = 0;
    while (*str != '\0') {
        str++;
        len++;
    }
    return len;
}
