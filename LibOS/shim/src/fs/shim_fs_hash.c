/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains functions to generate hash values for FS paths.
 */

#include "shim_fs.h"
#include "shim_internal.h"

static HASHTYPE __hash(const char* p, size_t len) {
    HASHTYPE hash = 0;
    HASHTYPE tmp;

    for (; len >= sizeof(hash); p += sizeof(hash), len -= sizeof(hash)) {
        memcpy(&tmp, p, sizeof(tmp)); /* avoid pointer alignment issues */
        hash += tmp;
        hash *= 9;
    }

    if (len) {
        HASHTYPE rest = 0;
        for (; len > 0; p++, len--) {
            rest <<= 8;
            rest += (HASHTYPE)*p;
        }
        hash += rest;
        hash *= 9;
    }

    return hash;
}

HASHTYPE hash_path(const char* path, size_t size) {
    HASHTYPE digest = 0;

    const char* elem_start = path;
    const char* c          = path;

    for (; c < path + size && *c; c++) {
        if (*c == '/') {
            digest ^= __hash(elem_start, c - elem_start);
            elem_start = c + 1;
        }
    }

    digest ^= __hash(elem_start, c - elem_start);
    return digest;
}

HASHTYPE rehash_name(HASHTYPE parent_hbuf, const char* name, size_t size) {
    return parent_hbuf ^ __hash(name, size);
}

HASHTYPE rehash_path(HASHTYPE ancestor_hbuf, const char* path, size_t size) {
    return ancestor_hbuf ^ hash_path(path, size);
}
