/* SPDX-License-Identifier: LGPL-3.0-or-later */

#include "api.h"

const char* strstr(const char* haystack, const char* needle) {
    size_t h_len = strlen(haystack);
    size_t n_len = strlen(needle);
    unsigned int o = 0;

    if (n_len == 0)
        return haystack;

    if (h_len < n_len)
        return NULL;

    while (o <= h_len - n_len) {
        size_t i = 0;
        while (i < n_len && haystack[o + i] == needle[i])
            i++;
        if (i == n_len)
            return &haystack[o];
        o++;
    }
    return NULL;
}
