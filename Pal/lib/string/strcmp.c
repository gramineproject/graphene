/* SPDX-License-Identifier: LGPL-3.0-or-later */

#include "api.h"

int strcmp(const char* lhs, const char* rhs) {
    while (*lhs == *rhs && *lhs) {
        lhs++;
        rhs++;
    }
    return *(unsigned char*)lhs - *(unsigned char*)rhs;
}
