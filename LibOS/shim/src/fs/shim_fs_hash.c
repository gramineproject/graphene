/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2014 Stony Brook University
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

/*
 * shim_fs_hash.c
 *
 * This file contains functions to generate hash values for FS paths.
 */

#include <shim_internal.h>
#include <shim_fs.h>
#include <shim_utils.h>

#include <pal.h>
#include <pal_error.h>

static inline unsigned int fold_hash(unsigned long hash)
{
    hash += hash >> (8*sizeof(int));
    return hash;
}

uint64_t hash_one(const char *name, unsigned int len)
{
    unsigned long a = 0;
    unsigned long mask = 0;
    uint64_t hash = 0;

    //debug ("Hashing %s, len %d seed %llx\n", name, len, hash);

    for (;;) {
        if (len < sizeof(unsigned long)) {
            a = 0;
            while (len) {
                a += *name;
                a <<= 8;
                name++;
                len--;
            }
        } else {
            a = *((unsigned long *) name);
            len -= sizeof(unsigned long);
        }
        hash += a;
        hash *= 9;
        name += sizeof(unsigned long);
        if (!len)
            goto done;
    }
    mask = ~(~0ul << len*8);
    hash += mask & a;
done:
    hash = fold_hash(hash);
    //debug("Hash returning %llx\n", hash);
    return hash;
}

static inline int __check_sep (int c, const char * sep)
{
    if (!*sep)
        return 0;

    if (!*(sep + 1))
        return c == *sep;

    if (!*(sep + 2))
        return c == *sep || c == *(sep + 1);

    for (const char * t = sep ; *sep ; sep++)
        if (c == *t)
            return 1;

    return 0;
}

static inline uint64_t __hash_path (const char * path,
                                    int size, const char * sep)
{
    uint64_t hash = 0;
    uint64_t digest = 0;

    const char * next_name = path;
    const char * c = path;
    while (c < path + size && *c) {
        if (__check_sep(*c, sep)) {
            if (next_name < c) {
                hash = hash_one(next_name, c - next_name);
                digest ^= hash;
            }
            next_name = c + 1;
        }
        c++;
    }

    if (next_name < c) {
        hash = hash_one(next_name, c - next_name);
        digest ^= hash;
    }

    return digest;
}

HASHTYPE hash_path (const char * path, int size,
                    const char * sep)
{
    return  __hash_path(path, size, sep ? sep : "/");
}

HASHTYPE hash_parent_path (HASHTYPE hbuf, const char * path,
                           int * size, const char * sep)
{
    if (*size < 0)
        *size = strlen (path);

    if (*size == 0)
        goto zero;

    sep = sep ? sep : "/";

    const char * last_name = path + *size;
    const char * last_frame_end = path + *size;
    while (last_name > path) {
        if (__check_sep(*(last_name - 1), sep)) {
            if (last_name < last_frame_end)
                break;

            last_frame_end = last_name - 1;
        }
        last_name--;
    }

    const char * parent_end = last_name - 1;
    while (parent_end > path && !__check_sep(*parent_end, sep))
        parent_end--;

    if (parent_end <= path)
        goto zero;

    HASHTYPE hash = 0;
    hash = hash_one(last_name, last_frame_end - last_name);

    hbuf ^= hash;

    *size = parent_end - path;

    return hbuf;

zero:
    hbuf = 0;
    *size = 0;
    return 0;
}

HASHTYPE rehash_name (HASHTYPE parent_hbuf,
                      const char * name, int size)
{
    HASHTYPE ret = 0;
    ret = hash_one(name, size);
    ret ^= parent_hbuf;
    return ret;
}

HASHTYPE rehash_path (HASHTYPE ancestor_hbuf,
                      const char * path, int size, const char * sep)
{
    HASHTYPE ctx = 0;
    HASHTYPE digest = 0;
    HASHTYPE hbuf;

    sep = sep ? : "/";

    const char * next_name = path;
    const char * c = path;
    while (c < path + size && *c) {
        if (__check_sep(*c, sep)) {
            if (next_name < c) {
                ctx = hash_one(next_name, c - next_name);
                digest ^= ctx;
            }
            next_name = c + 1;
        }
        c++;
    }

    if (next_name < c) {
        ctx = hash_one(next_name, c - next_name);
        digest ^= ctx;
    }

    hbuf = ancestor_hbuf ^ digest;
    return hbuf;
}
