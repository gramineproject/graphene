/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Dmitrii Kuvaiskii <dmitrii.kuvaiskii@intel.com>
 */

#include <stdint.h>

#include "api.h"
#include "toml.h"

/* returns a pointer to next '.' in `s` or null byte ending the string if no '.' was found */
static char* find_next_dot(char* s) {
    while (*s && *s != '.')
        s++;
    return s;
}

/* searches for a dotted-key (e.g. "fs.mount.lib1.type") from `root`; returns NULL if value for
 * such key is not found */
static toml_raw_t toml_raw_in_dottedkey(const toml_table_t* root, const char* _key) {
    char* key = strdup(_key);
    if (!key)
        return NULL;

    toml_raw_t raw = NULL;

    assert(root);
    const toml_table_t* cur_table = root;

    char* subkey     = key;
    char* subkey_end = find_next_dot(subkey);
    while (*subkey_end == '.') {
        *subkey_end = '\0';
        cur_table = toml_table_in(cur_table, subkey);
        if (!cur_table)
            goto out;

        subkey = subkey_end + 1;
        subkey_end = find_next_dot(subkey);
    }
    assert(*subkey_end == '\0');

    raw = toml_raw_in(cur_table, subkey);
out:
    free(key);
    return raw;
}

int toml_int_in(const toml_table_t* root, const char* key, int64_t defaultval, int64_t* retval) {
    toml_raw_t raw = toml_raw_in_dottedkey(root, key);
    if (!raw) {
        *retval = defaultval;
        return 0;
    }
    return toml_rtoi(raw, retval);
}

int toml_string_in(const toml_table_t* root, const char* key, char** retval) {
    toml_raw_t raw = toml_raw_in_dottedkey(root, key);
    if (!raw) {
        *retval = NULL;
        return 0;
    }
    return toml_rtos(raw, retval);
}

int toml_sizestring_in(const toml_table_t* root, const char* key, uint64_t defaultval,
                       uint64_t* retval) {
    toml_raw_t raw = toml_raw_in_dottedkey(root, key);
    if (!raw) {
        *retval = defaultval;
        return 0;
    }

    char* str = NULL;
    if (toml_rtos(raw, &str) < 0) {
        return -1;
    }
    assert(str);

    int64_t ret = parse_size_str(str);
    free(str);

    if (ret < 0)
        return -1;

    *retval = (uint64_t)ret;
    return 0;
}
