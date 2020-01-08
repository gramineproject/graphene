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
 * config.c
 *
 * This file contains functions to read app config (manifest) file and create
 * a tree to lookup / access config values.
 */

#include <api.h>
#include <list.h>
#include <pal_error.h>

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

static int __del_config(struct config_store* store, LISTP_TYPE(config)* root, struct config* p,
                        const char* key) {
    struct config* e;
    struct config* found = NULL;
    size_t len = 0;
    for (; key[len]; len++)
        if (key[len] == '.')
            break;

    LISTP_FOR_EACH_ENTRY(e, root, siblings) {
        if (e->klen == len && !memcmp(e->key, key, len)) {
            found = e;
            break;
        }
    }

    if (!found)
        return -PAL_ERROR_INVAL;

    if (key[len]) {
        if (found->val)
            return -PAL_ERROR_INVAL;
        int ret = __del_config(store, &found->children, found, key + len + 1);
        if (ret < 0)
            return ret;
        if (!LISTP_EMPTY(&found->children))
            return 0;
    } else {
        if (!found->val)
            return -PAL_ERROR_INVAL;
    }

    if (p)
        p->vlen -= (found->klen + 1);
    LISTP_DEL(found, root, siblings);
    LISTP_DEL(found, &store->entries, list);
    if (found->buf)
        store->free(found->buf);
    store->free(found);

    return 0;
}

int set_config(struct config_store* store, const char* key, const char* val) {
    if (!key)
        return -PAL_ERROR_INVAL;

    if (!val) { /* deletion */
        return __del_config(store, &store->root, 0, key);
    }

    int klen = strlen(key);
    int vlen = strlen(val);

    char* buf = store->malloc(klen + vlen + 2);
    if (!buf)
        return -PAL_ERROR_NOMEM;

    memcpy(buf, key, klen + 1);
    memcpy(buf + klen + 1, val, vlen + 1);

    struct config* e = __get_config(store, key);
    if (e) {
        e->val  = buf + klen + 1;
        e->vlen = vlen;
        e->buf  = buf;
    } else {
        int ret = __add_config(store, buf, klen, buf + klen + 1, vlen, &e);
        if (ret < 0) {
            store->free(buf);
            return ret;
        }
        e->buf = buf;
    }

    return 0;
}

int read_config(struct config_store* store, int (*filter)(const char* key, int ken),
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

        if (!filter || !filter(key, klen)) {
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

int free_config(struct config_store* store) {
    struct config* e;
    struct config* n;
    LISTP_FOR_EACH_ENTRY_SAFE(e, n, &store->entries, list) {
        store->free(e->buf);
        store->free(e);
    }

    INIT_LISTP(&store->root);
    INIT_LISTP(&store->entries);
    return 0;
}

static int __dup_config(const struct config_store* ss, const LISTP_TYPE(config) * sr,
                        struct config_store* ts, LISTP_TYPE(config) * tr, void** data,
                        size_t* size) {
    struct config* e;
    struct config* new;

    LISTP_FOR_EACH_ENTRY(e, sr, siblings) {
        char* key = NULL;
        char* val = NULL;
        char* buf = NULL;
        int need = 0;

        if (e->key) {
            if (*size > e->klen) {
                key = *data;
                *data += e->klen;
                *size -= e->klen;
                memcpy(key, e->key, e->klen);
            } else {
                need += e->klen;
            }
        }
        if (e->val) {
            if (*size > e->vlen) {
                val = *data;
                *data += e->vlen;
                *size -= e->vlen;
                memcpy(val, e->val, e->vlen);
            } else {
                need += e->vlen;
            }
        }

        if (need) {
            buf = ts->malloc(need);
            if (!buf)
                return -PAL_ERROR_NOMEM;
        }

        if (e->key && !key) {
            key = buf;
            memcpy(key, e->key, e->klen);
        }

        if (e->val && !val) {
            val = buf + (key == buf ? e->klen : 0);
            memcpy(val, e->val, e->vlen);
        }

        new = ts->malloc(sizeof(struct config));
        if (!new)
            return -PAL_ERROR_NOMEM;

        new->key  = key;
        new->klen = e->klen;
        new->val  = val;
        new->vlen = e->vlen;
        new->buf  = buf;
        INIT_LIST_HEAD(new, list);
        LISTP_ADD_TAIL(new, &ts->entries, list);
        INIT_LISTP(&new->children);
        INIT_LIST_HEAD(new, siblings);
        LISTP_ADD_TAIL(new, tr, siblings);

        if (!LISTP_EMPTY(&e->children)) {
            int ret = __dup_config(ss, &e->children, ts, &new->children, data, size);
            if (ret < 0)
                return ret;
        }
    }

    return 0;
}

int copy_config(struct config_store* store, struct config_store* new_store) {
    INIT_LISTP(&new_store->root);
    INIT_LISTP(&new_store->entries);

    struct config* e;
    size_t size = 0;

    LISTP_FOR_EACH_ENTRY(e, &store->entries, list) {
        if (e->key)
            size += e->klen;
        if (e->val)
            size += e->vlen;
    }

    void* data = new_store->malloc(size);

    if (!data)
        return -PAL_ERROR_NOMEM;

    void* dataptr = data;
    size_t datasz = size;

    new_store->raw_data = data;
    new_store->raw_size = size;

    return __dup_config(store, &store->root, new_store, &new_store->root, &dataptr, &datasz);
}

static int __write_config(void* f, int (*write)(void*, void*, int), struct config_store* store,
                          LISTP_TYPE(config) * root, char* keybuf, int klen,
                          unsigned long* offset) {
    struct config* e;
    int ret;
    char* buf = NULL;
    int bufsz = 0;

    LISTP_FOR_EACH_ENTRY(e, root, siblings) {
        if (e->val) {
            int total = klen + e->klen + e->vlen + 2;

            while (total > bufsz) {
                bufsz += CONFIG_MAX;
                buf = __alloca(CONFIG_MAX);
            }

            memcpy(buf, keybuf, klen);
            memcpy(buf + klen, e->key, e->klen);
            buf[klen + e->klen] = '=';
            memcpy(buf + total - e->vlen - 1, e->val, e->vlen);
            buf[total - 1] = '\n';

            ret = write(f, buf, total);
            if (ret < 0)
                return ret;

            *offset += total;
        } else {
            if (klen + e->klen + 1 > CONFIG_MAX)
                return -PAL_ERROR_TOOLONG;

            memcpy(keybuf + klen, e->key, e->klen);
            keybuf[klen + e->klen] = '.';

            if ((ret = __write_config(f, write, store, &e->children, keybuf, klen + e->klen + 1,
                                      offset)) < 0)
                return ret;
        }
    }

    return 0;
}

int write_config(void* f, int (*write)(void*, void*, int), struct config_store* store) {
    char buf[CONFIG_MAX];
    unsigned long offset = 0;

    return __write_config(f, write, store, &store->root, buf, 0, &offset);
}
