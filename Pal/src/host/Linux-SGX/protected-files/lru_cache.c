/* Copyright (C) 2019-2020 Invisible Things Lab
                           Rafal Wojdyla <omeg@invisiblethingslab.com>

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
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/* Least-recently used cache, used by the protected file implementation for optimizing
   data and MHT node access */

#include <assert.h>
#include <list.h>
#include <uthash.h>
#include "lru_cache.h"

#ifdef IN_PAL
    #include "pal_internal.h"
    #include "pal_linux.h"
#else
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>

noreturn void __abort(void) {
    exit(-1);
}
#endif

DEFINE_LIST(_lruc_list_node);
typedef struct _lruc_list_node {
    LIST_TYPE(_lruc_list_node) list;
    uint64_t key;
} lruc_list_node_t;
DEFINE_LISTP(_lruc_list_node);

typedef struct _lruc_map_node {
    uint64_t key;
    void* data;
    lruc_list_node_t* list_ptr;
    UT_hash_handle hh;
} lruc_map_node_t;

struct lruc_context {
    /* list and map both contain the same objects (list contains keys, map contains actual data).
     * They're kept in sync so that map is used for fast lookups and list is used for fast LRU.
     */
    LISTP_TYPE(_lruc_list_node) list;
    lruc_map_node_t* map;
    lruc_list_node_t* current;
};

lruc_context_t lruc_create(void) {
    lruc_context_t lruc = calloc(1, sizeof(*lruc));
    if (!lruc)
        return NULL;

    INIT_LISTP(&lruc->list);
    lruc->map = NULL;
    lruc->current = NULL;
    return lruc;
}

static lruc_map_node_t* get_map_node(lruc_context_t lruc, uint64_t key) {
    lruc_map_node_t* mn = NULL;
    HASH_FIND(hh, lruc->map, &key, sizeof(key), mn);
    return mn;
}

void lruc_destroy(lruc_context_t lruc) {
    struct _lruc_list_node* ln;
    struct _lruc_list_node* tmp;
    lruc_map_node_t* mn;

    LISTP_FOR_EACH_ENTRY_SAFE(ln, tmp, &lruc->list, list) {
        mn = get_map_node(lruc, ln->key);
        if (mn) {
            HASH_DEL(lruc->map, mn);
            free(mn);
        }
        LISTP_DEL(ln, &lruc->list, list);
        free(ln);
    }

    assert(LISTP_EMPTY(&lruc->list));
    assert(HASH_COUNT(lruc->map) == 0);
    free(lruc);
}

bool lruc_add(lruc_context_t lruc, uint64_t key, void* data) {
    lruc_map_node_t* map_node = calloc(1, sizeof(*map_node));
    if (!map_node)
        return false;

    lruc_list_node_t* list_node = calloc(1, sizeof(*list_node));
    if (!list_node) {
        free(map_node);
        return false;
    }

    list_node->key = key;
    map_node->key = key;
    LISTP_ADD(list_node, &lruc->list, list);
    __attribute__((unused)) lruc_map_node_t* mn = get_map_node(lruc, key);
    assert(mn == NULL);
    map_node->data = data;
    map_node->list_ptr = list_node;
    HASH_ADD(hh, lruc->map, key, sizeof(key), map_node);
    return true;
}

void* lruc_find(lruc_context_t lruc, uint64_t key) {
    lruc_map_node_t* mn = get_map_node(lruc, key);
    if (mn)
        return mn->data;
    return NULL;
}

void* lruc_get(lruc_context_t lruc, uint64_t key) {
    lruc_map_node_t* mn = get_map_node(lruc, key);
    if (!mn)
        return NULL;
    lruc_list_node_t* ln = mn->list_ptr;
    assert(ln != NULL);
    // move node to the front of the list
    LISTP_DEL(ln, &lruc->list, list);
    LISTP_ADD(ln, &lruc->list, list);
    return mn->data;
}

/* TODO: sync with list macro changes (use LISTP_GET_SIZE) */
size_t lruc_size(lruc_context_t lruc) {
    lruc_list_node_t* ln;
    size_t count = 0;
    LISTP_FOR_EACH_ENTRY(ln, &lruc->list, list)
        count++;
    assert(count == HASH_COUNT(lruc->map));
    return count;
}

void* lruc_get_first(lruc_context_t lruc) {
    if (LISTP_EMPTY(&lruc->list))
        return NULL;

    lruc->current = LISTP_FIRST_ENTRY(&lruc->list, /*unused*/0, list);
    lruc_map_node_t* mn = get_map_node(lruc, lruc->current->key);
    assert(mn != NULL);
    return mn->data;
}

void* lruc_get_next(lruc_context_t lruc) {
    if (LISTP_EMPTY(&lruc->list) || !lruc->current)
        return NULL;

    lruc->current = LISTP_NEXT_ENTRY(lruc->current, &lruc->list, list);
    if (!lruc->current)
        return NULL;

    lruc_map_node_t* mn = get_map_node(lruc, lruc->current->key);
    assert(mn != NULL);
    return mn->data;
}

void* lruc_get_last(lruc_context_t lruc) {
    if (LISTP_EMPTY(&lruc->list))
        return NULL;

    lruc_list_node_t* ln = LISTP_LAST_ENTRY(&lruc->list, /*unused*/0, list);
    lruc_map_node_t* mn = get_map_node(lruc, ln->key);
    assert(mn != NULL);
    return mn->data;
}

void lruc_remove_last(lruc_context_t lruc) {
    if (LISTP_EMPTY(&lruc->list))
        return;

    lruc_list_node_t* ln = LISTP_LAST_ENTRY(&lruc->list, /*unused*/0, list);
    LISTP_DEL(ln, &lruc->list, list);
    lruc_map_node_t* mn = get_map_node(lruc, ln->key);
    assert(mn != NULL);
    HASH_DEL(lruc->map, mn);
    free(ln);
    free(mn);
}

#ifndef IN_PAL
void lruc_test(void) {
    uint64_t a=1, b=2, c=3, d=4;
    printf("\n=== LRUC TEST ===\n");
    lruc_context_t lruc = lruc_create();
    printf("empty size: %zu\n", lruc_size(lruc));

    lruc_add(lruc, a, &a);
    printf("after add 1 size: %zu\n", lruc_size(lruc));
    uint64_t* x = lruc_find(lruc, a);
    #define X (x?*x:0)
    printf("find(1): %lu\n", X);

    lruc_add(lruc, b, &b);
    printf("after add 2 size: %zu\n", lruc_size(lruc));
    x = lruc_find(lruc, a);
    printf("find(1): %lu\n", X);
    x = lruc_find(lruc, b);
    printf("find(2): %lu\n", X);

    lruc_add(lruc, c, &c);
    printf("after add 3 size: %zu\n", lruc_size(lruc));
    x = lruc_find(lruc, a);
    printf("find(1): %lu\n", X);
    x = lruc_find(lruc, b);
    printf("find(2): %lu\n", X);
    x = lruc_find(lruc, c);
    printf("find(3): %lu\n", X);

    lruc_add(lruc, d, &d);
    printf("after add 4 size: %zu\n", lruc_size(lruc));
    x = lruc_find(lruc, a);
    printf("find(1): %lu\n", X);
    x = lruc_find(lruc, b);
    printf("find(2): %lu\n", X);
    x = lruc_find(lruc, c);
    printf("find(3): %lu\n", X);
    x = lruc_find(lruc, d);
    printf("find(4): %lu\n", X);

    x = lruc_get(lruc, a);
    printf("after get 1 size: %zu, %lu\n", lruc_size(lruc), X);
    x = lruc_get(lruc, b);
    printf("after get 2 size: %zu, %lu\n", lruc_size(lruc), X);
    x = lruc_get(lruc, c);
    printf("after get 3 size: %zu, %lu\n", lruc_size(lruc), X);
    x = lruc_get(lruc, d);
    printf("after get 4 size: %zu, %lu\n", lruc_size(lruc), X);

    lruc_remove_last(lruc);
    x = lruc_get(lruc, a);
    printf("after get 1 size: %zu, %lu\n", lruc_size(lruc), X);
    x = lruc_get(lruc, b);
    printf("after get 2 size: %zu, %lu\n", lruc_size(lruc), X);
    x = lruc_get(lruc, c);
    printf("after get 3 size: %zu, %lu\n", lruc_size(lruc), X);
    x = lruc_get(lruc, d);
    printf("after get 4 size: %zu, %lu\n", lruc_size(lruc), X);

    x = lruc_get(lruc, b);
    lruc_remove_last(lruc);
    x = lruc_find(lruc, a);
    printf("after find 1 size: %zu, %lu\n", lruc_size(lruc), X);
    x = lruc_find(lruc, b);
    printf("after find 2 size: %zu, %lu\n", lruc_size(lruc), X);
    x = lruc_find(lruc, c);
    printf("after find 3 size: %zu, %lu\n", lruc_size(lruc), X);
    x = lruc_find(lruc, d);
    printf("after find 4 size: %zu, %lu\n", lruc_size(lruc), X);
#undef X
    lruc_destroy(lruc);
}
#endif
