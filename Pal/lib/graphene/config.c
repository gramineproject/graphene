/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains functions to read app config (manifest) file and create a tree to
 * lookup / access config values.
 */

#include "api.h"
#include "hex.h"
#include "list.h"
#include "pal_error.h"

DEFINE_LIST(config);
struct config {
    const char* key;
    const char* val;
    size_t klen, vlen; /* for leaf nodes, vlen stores the size of config
                          values; for branch nodes, vlen stores the sum
                          of config value lengths plus one of all the
                          immediate children. */
    char* buf;
    LIST_TYPE(config) list;
    LISTP_TYPE(config) children;
    LIST_TYPE(config) siblings;
};

static int __add_config(struct config_store* store, const char* key, size_t klen, const char* val,
                        size_t vlen, struct config** entry) {
    LISTP_TYPE(config)* list = &store->root;
    struct config* e         = NULL;
    struct config* parent    = NULL;

    while (klen) {
        if (e && e->val)
            return -PAL_ERROR_INVAL;

        const char* token = key;
        size_t len        = 0;
        for (; len < klen; len++)
            if (token[len] == '.')
                break;

        LISTP_FOR_EACH_ENTRY(e, list, siblings) {
            if (e->klen == len && !memcmp(e->key, token, len))
                goto next;
        }

        e = store->malloc(sizeof(struct config));
        if (!e)
            return -PAL_ERROR_NOMEM;

        e->key  = token;
        e->klen = len;
        e->val  = NULL;
        e->vlen = 0;
        e->buf  = NULL;
        INIT_LIST_HEAD(e, list);
        LISTP_ADD_TAIL(e, &store->entries, list);
        INIT_LISTP(&e->children);
        INIT_LIST_HEAD(e, siblings);
        LISTP_ADD_TAIL(e, list, siblings);
        if (parent)
            parent->vlen += (len + 1);

    next:
        if (len < klen)
            len++;
        key += len;
        klen -= len;
        list   = &e->children;
        parent = e;
    }

    if (!e || e->val || !LISTP_EMPTY(&e->children))
        return -PAL_ERROR_INVAL;

    e->val  = val;
    e->vlen = vlen;

    if (entry)
        *entry = e;

    return 0;
}

static struct config* __get_config(struct config_store* store, const char* key) {
    LISTP_TYPE(config)* list = &store->root;
    struct config* e         = NULL;

    while (*key) {
        const char* token = key;
        size_t len        = 0;
        for (; token[len]; len++)
            if (token[len] == '.')
                break;

        LISTP_FOR_EACH_ENTRY(e, list, siblings) {
            if (e->klen == len && !memcmp(e->key, token, len))
                goto next;
        }

        return NULL;

    next:
        if (token[len])
            len++;
        key += len;
        list = &e->children;
    }

    return e;
}

ssize_t get_config(struct config_store* store, const char* key, char* val_buf, size_t buf_size) {
    struct config* e = __get_config(store, key);

    if (!e || !e->val)
        return -PAL_ERROR_INVAL;

    if (e->vlen >= buf_size)
        return -PAL_ERROR_TOOLONG;

    memcpy(val_buf, e->val, e->vlen);
    val_buf[e->vlen] = 0;
    return e->vlen;
}

int get_config_entries(struct config_store* store, const char* key, char* key_buf,
                       size_t key_bufsize) {
    struct config* e = __get_config(store, key);

    if (!e || e->val)
        return -PAL_ERROR_INVAL;

    LISTP_TYPE(config)* children = &e->children;
    int nentries                 = 0;

    LISTP_FOR_EACH_ENTRY(e, children, siblings) {
        if (e->klen + 1 > key_bufsize)
            return -PAL_ERROR_TOOLONG;
        memcpy(key_buf, e->key, e->klen);
        key_buf[e->klen] = 0;
        key_buf += e->klen + 1;
        key_bufsize -= e->klen + 1;
        nentries++;
    }

    return nentries;
}

ssize_t get_config_entries_size(struct config_store* store, const char* key) {
    struct config* e = __get_config(store, key);

    if (!e || e->val)
        return -PAL_ERROR_INVAL;

    return e->vlen;
}

int read_config(struct config_store* store, bool (*filter)(const char* key, size_t klen),
                const char** errstring) {
    INIT_LISTP(&store->root);
    INIT_LISTP(&store->entries);

    char* ptr     = store->raw_data;
    char* ptr_end = store->raw_data + store->raw_size;

    const char* err = "unknown error";

#define IS_SPACE(c) ((c) == ' ' || (c) == '\t')
#define IS_BREAK(c) ((c) == '\r' || (c) == '\n')
#define IS_VALID(c)                                                                            \
    (((c) >= 'A' && (c) <= 'Z') || ((c) >= 'a' && (c) <= 'z') || ((c) >= '0' && (c) <= '9') || \
     (c) == '_')

    register int skipping = 0;

#define IS_SKIP(p)                  \
    (skipping ? ({                  \
        if (IS_BREAK(*(p)))         \
            skipping = 0;           \
        1;                          \
    })                              \
              : ((*(p)) == '#' ? ({ \
                    skipping = 1;   \
                    1;              \
                })                  \
                               : IS_BREAK(*(p))))

#define RANGE (ptr < ptr_end)
#define GOTO_INVAL(msg) \
    ({                  \
        err = msg;      \
        goto inval;     \
    })
#define CHECK_PTR(msg) \
    if (!RANGE)        \
    GOTO_INVAL(msg)

    while (RANGE) {
        /* Skip the comment lines, empty lines and whitespaces before the key */
        for (; RANGE && (IS_SKIP(ptr) || IS_SPACE(*ptr)); ptr++)
            ;

        if (!(RANGE))
            break;

        if (!IS_VALID(*ptr))
            GOTO_INVAL("invalid start of key");

        char* key = ptr;
        for (; RANGE; ptr++) {
            char* pptr = ptr;

            /* Stop when meeting an invalid character */
            for (; RANGE && IS_VALID(*ptr); ptr++)
                ;
            CHECK_PTR("stream ended at key");

            if (pptr == ptr)
                GOTO_INVAL("key token with zero length");

            if (*ptr != '.')
                break;
        }

        int klen = ptr - key;

        /* Skip whitespaces between key portion and equal mark */
        for (; RANGE && IS_SPACE(*ptr); ptr++)
            ;
        CHECK_PTR("stream ended at key portion");

        if (*ptr != '=')
            GOTO_INVAL("equal mark expected");

        ptr++;

        /* Skip whitespaces between equal mark and value portion */
        for (; RANGE && IS_SPACE(*ptr); ptr++)
            ;
        CHECK_PTR("stream ended at equal mark");

        char* val = NULL;
        int vlen;
        if (*ptr == '"') {
            val = ++ptr;
            while (RANGE && *ptr != '"') {
                ptr++;
            }
            CHECK_PTR("stream ended without closing quote");
            vlen = ptr - val;
        } else {
            val        = ptr;
            char* last = ptr - 1;
            for (; RANGE && !IS_SKIP(ptr); ptr++)
                if (!IS_SPACE(*ptr))  // Skip the trailing whitespaces
                    last = ptr;
            vlen = last + 1 - val;
        }
        ptr++;

        if (!filter || filter(key, klen)) {
            int ret = __add_config(store, key, klen, val, vlen, NULL);
            if (ret < 0) {
                if (ret == -PAL_ERROR_TOOLONG)
                    GOTO_INVAL("key too long");
                if (ret == -PAL_ERROR_INVAL)
                    GOTO_INVAL("key format invalid");

                GOTO_INVAL("unknown error");
            }
        }
    }

    return 0;

inval:
    if (errstring)
        *errstring = err;

    return -PAL_ERROR_INVAL;

#undef CHECK_PTR
#undef GOTO_INVAL
#undef RANGE
#undef IS_SKIP
#undef IS_VALID
#undef IS_BREAK
#undef IS_SPACE
}
