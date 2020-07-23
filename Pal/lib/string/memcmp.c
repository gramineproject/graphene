/* SPDX-License-Identifier: LGPL-3.0-or-later */

#include <stdint.h>

#include "api.h"

int memcmp(const void* lhs, const void* rhs, size_t count) {
    const unsigned char* l = lhs;
    const unsigned char* r = rhs;
    while (count && *l == *r) {
        count--;
        l++;
        r++;
    }
    return count ? *l - *r : 0;
}
