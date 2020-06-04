/*
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

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
