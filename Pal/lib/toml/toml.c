/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2017 - 2019 CK Tan
 * Copyright (C) 2020 Intel Corporation
 */

#include "api.h"
#include "toml.h"

#include <assert.h>
#include <limits.h>
#include <stdint.h>

enum tokentype_t {
    TOML_TOKEN_INVALID,
    TOML_TOKEN_DOT,
    TOML_TOKEN_COMMA,
    TOML_TOKEN_EQUAL,
    TOML_TOKEN_LBRACE,
    TOML_TOKEN_RBRACE,
    TOML_TOKEN_NEWLINE,
    TOML_TOKEN_LBRACKET,
    TOML_TOKEN_RBRACKET,
    TOML_TOKEN_STRING,
};
typedef enum tokentype_t tokentype_t;

/* TOML has 3 data structures: value, array, table. Each of them can have identification key. */
typedef struct toml_keyval_t toml_keyval_t;
struct toml_keyval_t {
    const char* key; /* key to this value */
    const char* val; /* the raw value */
};

struct toml_array_t {
    const char* key; /* key to this array */
    int kind;        /* element kind: 'v'alue, 'a'rray, or 't'able */
    int type;        /* value kind: 'i'nt, 'd'ouble, 'b'ool, 's'tring, 't'ime, 'D'ate, 'T'ime */
    int nelem;       /* number of elements */
    union {
        char** val;
        toml_array_t** arr;
        toml_table_t** tab;
    } u;
};

struct toml_table_t {
    const char* key; /* key to this table */
    int implicit;    /* table was created implicitly */

    /* key-values in the table */
    int nkval;
    toml_keyval_t** kval;

    /* arrays in the table */
    int narr;
    toml_array_t** arr;

    /* tables in the table */
    int ntab;
    toml_table_t** tab;
};

typedef struct token_t token_t;
struct token_t {
    tokentype_t tok;
    int lineno;
    char* ptr; /* points into context->start */
    int len;
    int eof;
};

typedef struct tabpath_t tabpath_t;
struct tabpath_t {
    int cnt;
    token_t key[10];
};

typedef struct context_t context_t;
struct context_t {
    char* start;
    char* stop;
    char* errbuf;
    int errbufsz;

    token_t tok;
    toml_table_t* root;
    toml_table_t* curtab;

    struct {
        int top;
        char* key[10];
        token_t tok[10];
    } tpath;
};

#define STRINGIFY(x) #x
#define XSTRINGIFY(x) STRINGIFY(x)
#define FLINE __FILE__ ":" XSTRINGIFY(__LINE__)

static int next_token(context_t* ctx, int dotisspecial);
static int parse_keyval(context_t* ctx, toml_table_t* tab);
static void free_tab(toml_table_t* p);

static void e_outofmemory(context_t* ctx, const char* fline) {
    snprintf(ctx->errbuf, ctx->errbufsz, "ERROR: out of memory (%s)", fline);
}

static void e_internal_error(context_t* ctx, const char* fline) {
    snprintf(ctx->errbuf, ctx->errbufsz, "internal error (%s)", fline);
}

static void e_syntax_error(context_t* ctx, int lineno, const char* msg) {
    snprintf(ctx->errbuf, ctx->errbufsz, "line %d: %s", lineno, msg);
}

static void e_bad_key_error(context_t* ctx, int lineno) {
    snprintf(ctx->errbuf, ctx->errbufsz, "line %d: bad key", lineno);
}

static void e_key_exists_error(context_t* ctx, int lineno) {
    snprintf(ctx->errbuf, ctx->errbufsz, "line %d: key exists", lineno);
}

/* Below functions from ctype.h are adopted from Musl (standard MIT license):
 *   Copyright © 2005-2014 Rich Felker, et al. */
static int _islower(int c) {
    return (unsigned)c - 'a' < 26;
}

static int _toupper(int c) {
    if (_islower(c))
        return c & 0x5f;
    return c;
}

static int _isalpha(int c) {
    return ((unsigned)c | 32) - 'a' < 26;
}

static int _isdigit(int c) {
    return (unsigned)c - '0' < 10;
}

static int _isalnum(int c) {
    return _isalpha(c) || _isdigit(c);
}

static char* _strdup(const char* s) {
    int len = strlen(s);
    char* p = malloc(len + 1);
    if (p) {
        memcpy(p, s, len);
        p[len] = 0;
    }
    return p;
}

static char* _strndup(const char* s, size_t n) {
    size_t len = strnlen(s, n);
    char* p    = malloc(len + 1);
    if (p) {
        memcpy(p, s, len);
        p[len] = 0;
    }
    return p;
}

/* Convert a char in utf8 into UCS, and store it in *ret.
 * Return number of bytes consumed or -1 on failure. */
int toml_utf8_to_ucs(const char* orig, int len, int64_t* ret) {
    const unsigned char* buf = (const unsigned char*)orig;
    unsigned i = *buf++;
    int64_t v;

    /* 0x00000000 - 0x0000007F: 0xxxxxxx */
    if (0 == (i >> 7)) {
        if (len < 1)
            return -1;
        v    = i;
        *ret = v;
        return 1;
    }

    /* 0x00000080 - 0x000007FF: 110xxxxx 10xxxxxx */
    if (0x6 == (i >> 5)) {
        if (len < 2)
            return -1;
        v = i & 0x1f;
        for (int j = 0; j < 1; j++) {
            i = *buf++;
            if (0x2 != (i >> 6))
                return -1;
            v = (v << 6) | (i & 0x3f);
        }
        *ret = v;
        return (const char*)buf - orig;
    }

    /* 0x00000800 - 0x0000FFFF: 1110xxxx 10xxxxxx 10xxxxxx */
    if (0xE == (i >> 4)) {
        if (len < 3)
            return -1;
        v = i & 0x0F;
        for (int j = 0; j < 2; j++) {
            i = *buf++;
            if (0x2 != (i >> 6))
                return -1;
            v = (v << 6) | (i & 0x3f);
        }
        *ret = v;
        return (const char*)buf - orig;
    }

    /* 0x00010000 - 0x001FFFFF: 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx */
    if (0x1E == (i >> 3)) {
        if (len < 4)
            return -1;
        v = i & 0x07;
        for (int j = 0; j < 3; j++) {
            i = *buf++;
            if (0x2 != (i >> 6))
                return -1;
            v = (v << 6) | (i & 0x3f);
        }
        *ret = v;
        return (const char*)buf - orig;
    }

    /* 0x00200000 - 0x03FFFFFF: 111110xx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx */
    if (0x3E == (i >> 2)) {
        if (len < 5)
            return -1;
        v = i & 0x03;
        for (int j = 0; j < 4; j++) {
            i = *buf++;
            if (0x2 != (i >> 6))
                return -1;
            v = (v << 6) | (i & 0x3f);
        }
        *ret = v;
        return (const char*)buf - orig;
    }

    /* 0x04000000 - 0x7FFFFFFF: 1111110x 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx */
    if (0x7e == (i >> 1)) {
        if (len < 6)
            return -1;
        v = i & 0x01;
        for (int j = 0; j < 5; j++) {
            i = *buf++;
            if (0x2 != (i >> 6))
                return -1;
            v = (v << 6) | (i & 0x3f);
        }
        *ret = v;
        return (const char*)buf - orig;
    }
    return -1;
}

/* Convert a UCS char to utf8 code, and return it in buf.
 * Return number of bytes used in buf to encode the char, or -1 on error. */
int toml_ucs_to_utf8(int64_t code, char buf[6]) {
    /* The UCS code values 0xd800–0xdfff (UTF-16 surrogates) as well as 0xfffe and 0xffff
     * (UCS noncharacters) should not appear in conforming UTF-8 streams. */
    if (0xd800 <= code && code <= 0xdfff)
        return -1;
    if (0xfffe <= code && code <= 0xffff)
        return -1;

    /* 0x00000000 - 0x0000007F: 0xxxxxxx */
    if (code < 0)
        return -1;
    if (code <= 0x7F) {
        buf[0] = (unsigned char)code;
        return 1;
    }

    /* 0x00000080 - 0x000007FF: 110xxxxx 10xxxxxx */
    if (code <= 0x000007FF) {
        buf[0] = 0xc0 | (code >> 6);
        buf[1] = 0x80 | (code & 0x3f);
        return 2;
    }

    /* 0x00000800 - 0x0000FFFF: 1110xxxx 10xxxxxx 10xxxxxx */
    if (code <= 0x0000FFFF) {
        buf[0] = 0xe0 | (code >> 12);
        buf[1] = 0x80 | ((code >> 6) & 0x3f);
        buf[2] = 0x80 | (code & 0x3f);
        return 3;
    }

    /* 0x00010000 - 0x001FFFFF: 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx */
    if (code <= 0x001FFFFF) {
        buf[0] = 0xf0 | (code >> 18);
        buf[1] = 0x80 | ((code >> 12) & 0x3f);
        buf[2] = 0x80 | ((code >> 6) & 0x3f);
        buf[3] = 0x80 | (code & 0x3f);
        return 4;
    }

    /* 0x00200000 - 0x03FFFFFF: 111110xx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx */
    if (code <= 0x03FFFFFF) {
        buf[0] = 0xf8 | (code >> 24);
        buf[1] = 0x80 | ((code >> 18) & 0x3f);
        buf[2] = 0x80 | ((code >> 12) & 0x3f);
        buf[3] = 0x80 | ((code >> 6) & 0x3f);
        buf[4] = 0x80 | (code & 0x3f);
        return 5;
    }

    /* 0x04000000 - 0x7FFFFFFF: 1111110x 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx */
    if (code <= 0x7FFFFFFF) {
        buf[0] = 0xfc | (code >> 30);
        buf[1] = 0x80 | ((code >> 24) & 0x3f);
        buf[2] = 0x80 | ((code >> 18) & 0x3f);
        buf[3] = 0x80 | ((code >> 12) & 0x3f);
        buf[4] = 0x80 | ((code >> 6) & 0x3f);
        buf[5] = 0x80 | (code & 0x3f);
        return 6;
    }

    return -1;
}

static char* norm_lit_str(const char* src, int srclen, int multiline, char* errbuf, int errbufsz) {
    char* dst      = 0; /* will write to dst[] and return it */
    int max        = 0; /* max size of dst[] */
    int off        = 0; /* cur offset in dst[] */
    const char* sp = src;
    const char* sq = src + srclen;
    int ch;

    /* scan forward on src */
    for (;;) {
        if (off >= max - 10) { /* have some slack for misc stuff */
            if (max > INT_MAX - 50) {
                free(dst);
                snprintf(errbuf, errbufsz, "integer overflow");
                return 0;
            }
            max += 50;

            char* x = malloc(max);
            if (!x) {
                free(dst);
                snprintf(errbuf, errbufsz, "out of memory");
                return 0;
            }

            memcpy(x, dst, max - 50);
            free(dst);
            dst = x;
        }

        /* finished? */
        if (sp >= sq)
            break;

        ch = *sp++;
        /* control characters other than tab is not allowed */
        if ((0 <= ch && ch <= 0x08) || (0x0a <= ch && ch <= 0x1f) || (ch == 0x7f)) {
            if (!(multiline && (ch == '\r' || ch == '\n'))) {
                free(dst);
                snprintf(errbuf, errbufsz, "invalid char U+%04x", ch);
                return 0;
            }
        }

        // a plain copy suffice
        dst[off++] = ch;
    }

    dst[off++] = 0;
    return dst;
}

/* Convert src to raw unescaped utf-8 string. Returns NULL if error with errmsg in errbuf. */
static char* norm_basic_str(const char* src, int srclen, int multiline, char* errbuf,
                            int errbufsz) {
    char* dst      = 0; /* will write to dst[] and return it */
    int max        = 0; /* max size of dst[] */
    int off        = 0; /* cur offset in dst[] */
    const char* sp = src;
    const char* sq = src + srclen;
    int ch;

    /* scan forward on src */
    for (;;) {
        if (off >= max - 10) { /* have some slack for misc stuff */
            if (max > INT_MAX - 50) {
                free(dst);
                snprintf(errbuf, errbufsz, "integer overflow");
                return 0;
            }
            max += 50;

            char* x = malloc(max);
            if (!x) {
                free(dst);
                snprintf(errbuf, errbufsz, "out of memory");
                return 0;
            }

            memcpy(x, dst, max - 50);
            free(dst);
            dst = x;
        }

        /* finished? */
        if (sp >= sq)
            break;

        ch = *sp++;
        if (ch != '\\') {
            /* these chars must be escaped: U+0000 to U+0008, U+000A to U+001F, U+007F */
            if ((0 <= ch && ch <= 0x08) || (0x0a <= ch && ch <= 0x1f) || (ch == 0x7f)) {
                if (!(multiline && (ch == '\r' || ch == '\n'))) {
                    free(dst);
                    snprintf(errbuf, errbufsz, "invalid char U+%04x", ch);
                    return 0;
                }
            }

            // a plain copy suffice
            dst[off++] = ch;
            continue;
        }

        /* ch was backslash, we expect the escape char */
        if (sp >= sq) {
            snprintf(errbuf, errbufsz, "last backslash is invalid");
            free(dst);
            return 0;
        }

        /* for multi-line, we want to kill line-ending-backslash ... */
        if (multiline) {
            /* if there is only whitespace after the backslash ... */
            if (sp[strspn(sp, " \t\r")] == '\n') {
                /* skip all the following whitespaces */
                sp += strspn(sp, " \t\r\n");
                continue;
            }
        }

        /* get the escaped char */
        ch = *sp++;
        switch (ch) {
            case 'u':
            case 'U': {
                int64_t ucs = 0;
                int nhex    = (ch == 'u' ? 4 : 8);
                for (int i = 0; i < nhex; i++) {
                    if (sp >= sq) {
                        snprintf(errbuf, errbufsz, "\\%c expects %d hex chars", ch, nhex);
                        free(dst);
                        return 0;
                    }
                    ch    = *sp++;
                    int v = ('0' <= ch && ch <= '9')
                                ? ch - '0'
                                : (('A' <= ch && ch <= 'F') ? ch - 'A' + 10 : -1);
                    if (-1 == v) {
                        snprintf(errbuf, errbufsz, "invalid hex chars for \\u or \\U");
                        free(dst);
                        return 0;
                    }
                    ucs = ucs * 16 + v;
                }
                int n = toml_ucs_to_utf8(ucs, &dst[off]);
                if (-1 == n) {
                    snprintf(errbuf, errbufsz, "illegal ucs code in \\u or \\U");
                    free(dst);
                    return 0;
                }
                off += n;
            }
                continue;

            case 'b':
                ch = '\b';
                break;
            case 't':
                ch = '\t';
                break;
            case 'n':
                ch = '\n';
                break;
            case 'f':
                ch = '\f';
                break;
            case 'r':
                ch = '\r';
                break;
            case '"':
                ch = '"';
                break;
            case '\\':
                ch = '\\';
                break;
            default:
                snprintf(errbuf, errbufsz, "illegal escape char \\%c", ch);
                free(dst);
                return 0;
        }

        dst[off++] = ch;
    }

    dst[off++] = 0;
    return dst;
}

/* Normalize a key. Convert all special chars to raw unescaped utf-8 chars. */
static char* normalize_key(context_t* ctx, token_t strtok) {
    const char* sp = strtok.ptr;
    const char* sq = strtok.ptr + strtok.len;
    int lineno     = strtok.lineno;
    char* ret;
    int ch = *sp;
    char ebuf[80];

    /* handle quoted string */
    if (ch == '\'' || ch == '\"') {
        /* if ''' or """, take 3 chars off front and back. Else, take 1 char off. */
        int multiline = 0;
        if (sp[1] == ch && sp[2] == ch) {
            sp += 3, sq -= 3;
            multiline = 1;
        } else
            sp++, sq--;

        if (ch == '\'') {
            /* for single quote, take it verbatim. */
            if (!(ret = _strndup(sp, sq - sp))) {
                e_outofmemory(ctx, FLINE);
                return 0;
            }
        } else {
            /* for double quote, we need to normalize */
            ret = norm_basic_str(sp, sq - sp, multiline, ebuf, sizeof(ebuf));
            if (!ret) {
                e_syntax_error(ctx, lineno, ebuf);
                return 0;
            }
        }

        /* newlines are not allowed in keys */
        if (strchr(ret, '\n')) {
            free(ret);
            e_bad_key_error(ctx, lineno);
            return 0;
        }
        return ret;
    }

    /* for bare-key allow only this regex: [A-Za-z0-9_-]+ */
    const char* xp;
    for (xp = sp; xp != sq; xp++) {
        int k = *xp;
        if (_isalnum(k))
            continue;
        if (k == '_' || k == '-')
            continue;
        e_bad_key_error(ctx, lineno);
        return 0;
    }

    /* dup and return it */
    if (!(ret = _strndup(sp, sq - sp))) {
        e_outofmemory(ctx, FLINE);
        return 0;
    }
    return ret;
}

/* Look up key in tab. Return 0 if not found, or 'v'alue, 'a'rray or 't'able. */
static int check_key(toml_table_t* tab, const char* key, toml_keyval_t** ret_val,
                     toml_array_t** ret_arr, toml_table_t** ret_tab) {
    int i;
    void* dummy;

    if (!ret_tab)
        ret_tab = (toml_table_t**)&dummy;
    if (!ret_arr)
        ret_arr = (toml_array_t**)&dummy;
    if (!ret_val)
        ret_val = (toml_keyval_t**)&dummy;

    *ret_tab = 0;
    *ret_arr = 0;
    *ret_val = 0;

    for (i = 0; i < tab->nkval; i++) {
        if (0 == strcmp(key, tab->kval[i]->key)) {
            *ret_val = tab->kval[i];
            return 'v';
        }
    }
    for (i = 0; i < tab->narr; i++) {
        if (0 == strcmp(key, tab->arr[i]->key)) {
            *ret_arr = tab->arr[i];
            return 'a';
        }
    }
    for (i = 0; i < tab->ntab; i++) {
        if (0 == strcmp(key, tab->tab[i]->key)) {
            *ret_tab = tab->tab[i];
            return 't';
        }
    }
    return 0;
}

static int key_kind(toml_table_t* tab, const char* key) {
    return check_key(tab, key, 0, 0, 0);
}

/* Create a keyval in the table. */
static toml_keyval_t* create_keyval_in_table(context_t* ctx, toml_table_t* tab, token_t keytok) {
    /* first, normalize the key to be used for lookup; remember to free it if we error out */
    char* newkey = normalize_key(ctx, keytok);
    if (!newkey) {
        /* normalize_key() already updated ctx->errbuf */
        return 0;
    }

    /* if key exists: error out */
    toml_keyval_t* dest = 0;
    if (key_kind(tab, newkey)) {
        free(newkey);
        e_key_exists_error(ctx, keytok.lineno);
        return 0;
    }

    /* make a new entry */
    int n = tab->nkval;
    toml_keyval_t** base;
    if (0 == (base = (toml_keyval_t**)malloc((n + 1) * sizeof(*base)))) {
        free(newkey);
        e_outofmemory(ctx, FLINE);
        return 0;
    }
    memcpy(base, tab->kval, n * sizeof(*base));
    free(tab->kval);
    tab->kval = base;

    if (0 == (base[n] = (toml_keyval_t*)calloc(1, sizeof(*base[n])))) {
        free(newkey);
        e_outofmemory(ctx, FLINE);
        return 0;
    }
    dest = tab->kval[tab->nkval++];

    /* save the key in the new value struct */
    dest->key = newkey;
    return dest;
}

/* Create a table in the table. */
static toml_table_t* create_keytable_in_table(context_t* ctx, toml_table_t* tab, token_t keytok) {
    /* first, normalize the key to be used for lookup; remember to free it if we error out */
    char* newkey = normalize_key(ctx, keytok);
    if (!newkey) {
        /* normalize_key() already updated ctx->errbuf */
        return 0;
    }

    /* if key exists: error out */
    toml_table_t* dest = 0;
    if (check_key(tab, newkey, 0, 0, &dest)) {
        free(newkey); /* don't need this anymore */

        /* special case: if table exists, but was created implicitly ... */
        if (dest && dest->implicit) {
            /* we make it explicit now, and simply return it. */
            dest->implicit = 0;
            return dest;
        }
        e_key_exists_error(ctx, keytok.lineno);
        return 0;
    }

    /* create a new table entry */
    int n = tab->ntab;
    toml_table_t** base;
    if (0 == (base = (toml_table_t**)malloc((n + 1) * sizeof(*base)))) {
        free(newkey);
        e_outofmemory(ctx, FLINE);
        return 0;
    }
    memcpy(base, tab->tab, n * sizeof(*base));
    free(tab->tab);
    tab->tab = base;

    if (0 == (base[n] = (toml_table_t*)calloc(1, sizeof(*base[n])))) {
        free(newkey);
        e_outofmemory(ctx, FLINE);
        return 0;
    }
    dest = tab->tab[tab->ntab++];

    /* save the key in the new table struct */
    dest->key = newkey;
    return dest;
}

/* Create an array in the table. */
static toml_array_t* create_keyarray_in_table(context_t* ctx, toml_table_t* tab, token_t keytok,
                                              char kind) {
    /* first, normalize the key to be used for lookup; remember to free it if we error out */
    char* newkey = normalize_key(ctx, keytok);
    if (!newkey) {
        /* normalize_key() already updated ctx->errbuf */
        return 0;
    }

    /* if key exists: error out */
    if (key_kind(tab, newkey)) {
        free(newkey); /* don't need this anymore */
        e_key_exists_error(ctx, keytok.lineno);
        return 0;
    }

    /* make a new array entry */
    int n = tab->narr;
    toml_array_t** base;
    if (0 == (base = (toml_array_t**)malloc((n + 1) * sizeof(*base)))) {
        free(newkey);
        e_outofmemory(ctx, FLINE);
        return 0;
    }
    memcpy(base, tab->arr, n * sizeof(*base));
    free(tab->arr);
    tab->arr = base;

    if (0 == (base[n] = (toml_array_t*)calloc(1, sizeof(*base[n])))) {
        free(newkey);
        e_outofmemory(ctx, FLINE);
        return 0;
    }
    toml_array_t* dest = tab->arr[tab->narr++];

    /* save the key in the new array struct */
    dest->key  = newkey;
    dest->kind = kind;
    return dest;
}

/* Create an array in an array. */
static toml_array_t* create_array_in_array(context_t* ctx, toml_array_t* parent) {
    int n = parent->nelem;
    toml_array_t** base;
    if (0 == (base = (toml_array_t**)malloc((n + 1) * sizeof(*base)))) {
        e_outofmemory(ctx, FLINE);
        return 0;
    }
    memcpy(base, parent->u.arr, n * sizeof(*base));
    free(parent->u.arr);
    parent->u.arr = base;

    if (0 == (base[n] = (toml_array_t*)calloc(1, sizeof(*base[n])))) {
        e_outofmemory(ctx, FLINE);
        return 0;
    }

    return parent->u.arr[parent->nelem++];
}

/* Create a table in an array. */
static toml_table_t* create_table_in_array(context_t* ctx, toml_array_t* parent) {
    int n = parent->nelem;
    toml_table_t** base;
    if (0 == (base = (toml_table_t**)malloc((n + 1) * sizeof(*base)))) {
        e_outofmemory(ctx, FLINE);
        return 0;
    }
    memcpy(base, parent->u.tab, n * sizeof(*base));
    free(parent->u.tab);
    parent->u.tab = base;

    if (0 == (base[n] = (toml_table_t*)calloc(1, sizeof(*base[n])))) {
        e_outofmemory(ctx, FLINE);
        return 0;
    }

    return parent->u.tab[parent->nelem++];
}

static int skip_newlines(context_t* ctx, int isdotspecial) {
    while (ctx->tok.tok == TOML_TOKEN_NEWLINE) {
        if (-1 == next_token(ctx, isdotspecial)) {
            /* next_token() already updated ctx->errbuf */
            return -1;
        }
        if (ctx->tok.eof)
            break;
    }
    return 0;
}

/* We are at '{ ... }'. Parse the table. */
static int parse_table(context_t* ctx, toml_table_t* tab) {
    if (ctx->tok.tok != TOML_TOKEN_LBRACE) {
        e_syntax_error(ctx, ctx->tok.lineno, "expect a left brace");
        return -1;
    }

    if (-1 == next_token(ctx, 1)) {
        /* next_token() already updated ctx->errbuf */
        return -1;
    }

    for (;;) {
        if (ctx->tok.tok == TOML_TOKEN_NEWLINE) {
            e_syntax_error(ctx, ctx->tok.lineno, "newline not allowed in inline table");
            return -1;
        }

        /* until } */
        if (ctx->tok.tok == TOML_TOKEN_RBRACE)
            break;

        if (ctx->tok.tok != TOML_TOKEN_STRING) {
            e_syntax_error(ctx, ctx->tok.lineno, "expect a string");
            return -1;
        }

        if (-1 == parse_keyval(ctx, tab)) {
            /* parse_keyval() already updated ctx->errbuf */
            return -1;
        }

        if (ctx->tok.tok == TOML_TOKEN_NEWLINE) {
            e_syntax_error(ctx, ctx->tok.lineno, "newline not allowed in inline table");
            return -1;
        }

        /* on comma, continue to scan for next keyval */
        if (ctx->tok.tok == TOML_TOKEN_COMMA) {
            if (-1 == next_token(ctx, 1)) {
                /* next_token() already updated ctx->errbuf */
                return -1;
            }
            continue;
        }
        break;
    }

    if (ctx->tok.tok != TOML_TOKEN_RBRACE) {
        e_syntax_error(ctx, ctx->tok.lineno, "expect a right brace");
        return -1;
    }

    if (-1 == next_token(ctx, 1)) {
        /* next_token() already updated ctx->errbuf */
        return -1;
    }

    return 0;
}

static int valtype(const char* val) {
    toml_timestamp_t ts;
    if (*val == '\'' || *val == '"')
        return 's';
    if (0 == toml_rtob(val, 0))
        return 'b';
    if (0 == toml_rtoi(val, 0))
        return 'i';
    if (0 == toml_rtod(val, 0))
        return 'd';
    if (0 == toml_rtots(val, &ts)) {
        if (ts.year && ts.hour)
            return 'T'; /* timestamp */
        if (ts.year)
            return 'D'; /* date */
        return 't';     /* time */
    }
    return 'u'; /* unknown */
}

/* We are at '[...]' */
static int parse_array(context_t* ctx, toml_array_t* arr) {
    if (ctx->tok.tok != TOML_TOKEN_LBRACKET) {
        e_syntax_error(ctx, ctx->tok.lineno, "expect a left bracket");
        return -1;
    }

    if (-1 == next_token(ctx, 0)) {
        /* next_token() already updated ctx->errbuf */
        return -1;
    }

    for (;;) {
        if (-1 == skip_newlines(ctx, 0)) {
            /* skip_newlines() already updated ctx->errbuf */
            return -1;
        }

        /* until ] */
        if (ctx->tok.tok == TOML_TOKEN_RBRACKET)
            break;

        switch (ctx->tok.tok) {
            case TOML_TOKEN_STRING: {
                char* val = ctx->tok.ptr;
                int vlen  = ctx->tok.len;

                /* set array kind if this will be the first entry */
                if (arr->kind == 0)
                    arr->kind = 'v';
                /* check array kind */
                if (arr->kind != 'v') {
                    e_syntax_error(ctx, ctx->tok.lineno, "a string array can only contain strings");
                    return -1;
                }

                /* make a new value in array */
                char** tmp = (char**)malloc((arr->nelem + 1) * sizeof(*tmp));
                if (!tmp) {
                    e_outofmemory(ctx, FLINE);
                    return -1;
                }
                memcpy(tmp, arr->u.val, arr->nelem * sizeof(*tmp));
                free(arr->u.val);
                arr->u.val = tmp;
                if (!(val = _strndup(val, vlen))) {
                    e_outofmemory(ctx, FLINE);
                    return -1;
                }
                arr->u.val[arr->nelem++] = val;

                /* set array type if this is the first entry, or check that the types matched. */
                if (arr->nelem == 1)
                    arr->type = valtype(arr->u.val[0]);
                else if (arr->type != valtype(val)) {
                    e_syntax_error(ctx, ctx->tok.lineno,
                                   "array type mismatch while processing array of values");
                    return -1;
                }

                if (-1 == next_token(ctx, 0)) {
                    /* next_token() already updated ctx->errbuf */
                    return -1;
                }
                break;
            }

            case TOML_TOKEN_LBRACKET: { /* [ [array], [array] ... ] */
                /* set the array kind if this will be the first entry */
                if (arr->kind == 0)
                    arr->kind = 'a';
                /* check array kind */
                if (arr->kind != 'a') {
                    e_syntax_error(ctx, ctx->tok.lineno,
                                   "array type mismatch while processing array of arrays");
                    return -1;
                }

                toml_array_t* arr_in_arr = create_array_in_array(ctx, arr);
                if (!arr_in_arr) {
                    /* create_array_in_array() already updated ctx->errbuf */
                    return -1;
                }

                if (-1 == parse_array(ctx, arr_in_arr)) {
                    /* nested parse_array() already updated ctx->errbuf */
                    return -1;
                }
                break;
            }

            case TOML_TOKEN_LBRACE: { /* [ {table}, {table} ... ] */
                /* set the array kind if this will be the first entry */
                if (arr->kind == 0)
                    arr->kind = 't';
                /* check array kind */
                if (arr->kind != 't') {
                    e_syntax_error(ctx, ctx->tok.lineno,
                                   "array type mismatch while processing array of tables");
                    return -1;
                }

                toml_table_t* tbl = create_table_in_array(ctx, arr);
                if (!tbl) {
                    /* create_table_in_array() already updated ctx->errbuf */
                    return -1;
                }

                if (-1 == parse_table(ctx, tbl)) {
                    /* parse_table() already updated ctx->errbuf */
                    return -1;
                }
                break;
            }

            default:
                e_syntax_error(ctx, ctx->tok.lineno, "syntax error");
                return -1;
        }

        if (-1 == skip_newlines(ctx, 0)) {
            /* skip_newlines() already updated ctx->errbuf */
            return -1;
        }

        /* on comma, continue to scan for next element */
        if (ctx->tok.tok == TOML_TOKEN_COMMA) {
            if (-1 == next_token(ctx, 0)) {
                /* next_token() already updated ctx->errbuf */
                return -1;
            }
            continue;
        }
        break;
    }

    if (ctx->tok.tok != TOML_TOKEN_RBRACKET) {
        e_syntax_error(ctx, ctx->tok.lineno, "expect a right bracket");
        return -1;
    }

    if (-1 == next_token(ctx, 1)) {
        /* next_token() already updated ctx->errbuf */
        return -1;
    }

    return 0;
}

/* Handle lines like these:
     key = "value"
     key = [ array ]
     key = { table }
*/
static int parse_keyval(context_t* ctx, toml_table_t* tab) {
    token_t key = ctx->tok;

    if (ctx->tok.tok != TOML_TOKEN_STRING) {
        e_syntax_error(ctx, ctx->tok.lineno, "expect a string");
        return -1;
    }

    if (-1 == next_token(ctx, 1)) {
        /* next_token() already updated ctx->errbuf */
        return -1;
    }

    if (ctx->tok.tok == TOML_TOKEN_DOT) {
        /* handle inline dotted key, e.g.
             physical.color = "orange"
             physical.shape = "round"
        */
        toml_table_t* subtab = 0;
        {
            char* subtabstr = normalize_key(ctx, key);
            if (!subtabstr) {
                /* normalize_key() already updated ctx->errbuf */
                return -1;
            }

            subtab = toml_table_in(tab, subtabstr);
            free(subtabstr);
        }
        if (!subtab) {
            subtab = create_keytable_in_table(ctx, tab, key);
            if (!subtab) {
                /* create_keytable_in_table() already updated ctx->errbuf */
                return -1;
            }
        }

        if (-1 == next_token(ctx, 1)) {
            /* next_token() already updated ctx->errbuf */
            return -1;
        }

        if (-1 == parse_keyval(ctx, subtab)) {
            /* parse_keyval() already updated ctx->errbuf */
            return -1;
        }
        return 0;
    }

    if (ctx->tok.tok != TOML_TOKEN_EQUAL) {
        e_syntax_error(ctx, ctx->tok.lineno, "missing =");
        return -1;
    }

    if (-1 == next_token(ctx, 0)) {
        /* next_token() already updated ctx->errbuf */
        return -1;
    }

    switch (ctx->tok.tok) {
        case TOML_TOKEN_STRING: { /* key = "value" */
            toml_keyval_t* keyval = create_keyval_in_table(ctx, tab, key);
            if (!keyval) {
                /* create_keyval_in_table() already updated ctx->errbuf */
                return -1;
            }

            token_t val = ctx->tok;
            assert(keyval->val == 0);
            keyval->val = _strndup(val.ptr, val.len);
            if (!keyval->val) {
                e_outofmemory(ctx, FLINE);
                return -1;
            }

            if (-1 == next_token(ctx, 1)) {
                /* next_token() already updated ctx->errbuf */
                return -1;
            }

            return 0;
        }

        case TOML_TOKEN_LBRACKET: { /* key = [ array ] */
            toml_array_t* arr = create_keyarray_in_table(ctx, tab, key, 0);
            if (!arr) {
                /* create_keyarray_in_table() already updated ctx->errbuf */
                return -1;
            }

            if (-1 == parse_array(ctx, arr)) {
                /* parse_array() already updated ctx->errbuf */
                return -1;
            }
            return 0;
        }

        case TOML_TOKEN_LBRACE: { /* key = { table } */
            toml_table_t* nxttab = create_keytable_in_table(ctx, tab, key);
            if (!nxttab) {
                /* create_keytable_in_table() already updated ctx->errbuf */
                return -1;
            }
            if (-1 == parse_table(ctx, nxttab)) {
                /* parse_table() already updated ctx->errbuf */
                return -1;
            }
            return 0;
        }

        default:
            e_syntax_error(ctx, ctx->tok.lineno, "syntax error");
            return -1;
    }

    return 0;
}

/* at [x.y.z] or [[x.y.z]]. Scan forward and fill tabpath until it enters ] or ]]. There will be
 * at least one entry on return. */
static int fill_tabpath(context_t* ctx) {
    int lineno = ctx->tok.lineno;
    int i;

    /* clear tpath */
    for (i = 0; i < ctx->tpath.top; i++) {
        char** p = &ctx->tpath.key[i];
        free(*p);
        *p = 0;
    }
    ctx->tpath.top = 0;

    for (;;) {
        if (ctx->tpath.top >= 10) {
            e_syntax_error(ctx, lineno, "table path is too deep; max allowed is 10.");
            return -1;
        }

        if (ctx->tok.tok != TOML_TOKEN_STRING) {
            e_syntax_error(ctx, lineno, "invalid or missing key");
            return -1;
        }

        char* normkey = normalize_key(ctx, ctx->tok);
        if (!normkey) {
            /* normalize_key() already updated ctx->errbuf */
            return -1;
        }

        ctx->tpath.tok[ctx->tpath.top] = ctx->tok;
        ctx->tpath.key[ctx->tpath.top] = normkey;
        ctx->tpath.top++;

        if (-1 == next_token(ctx, 1)) {
            /* next_token() already updated ctx->errbuf */
            return -1;
        }

        if (ctx->tok.tok == TOML_TOKEN_RBRACKET)
            break;

        if (ctx->tok.tok != TOML_TOKEN_DOT) {
            e_syntax_error(ctx, lineno, "invalid key");
            return -1;
        }

        if (-1 == next_token(ctx, 1)) {
            /* next_token() already updated ctx->errbuf */
            return -1;
        }
    }

    if (ctx->tpath.top <= 0) {
        e_syntax_error(ctx, lineno, "empty table selector");
        return -1;
    }

    return 0;
}

/* Walk tabpath from root, and create new tables on the way. Sets ctx->curtab to the final table. */
static int walk_tabpath(context_t* ctx) {
    /* start from root */
    toml_table_t* curtab = ctx->root;

    for (int i = 0; i < ctx->tpath.top; i++) {
        const char* key = ctx->tpath.key[i];

        toml_keyval_t* nextval = 0;
        toml_array_t* nextarr  = 0;
        toml_table_t* nexttab  = 0;
        switch (check_key(curtab, key, &nextval, &nextarr, &nexttab)) {
            case 't':
                /* found a table. nexttab is where we will go next. */
                break;

            case 'a':
                /* found an array. nexttab is the last table in the array. */
                if (nextarr->kind != 't') {
                    e_internal_error(ctx, FLINE);
                    return -1;
                }
                if (nextarr->nelem == 0) {
                    e_internal_error(ctx, FLINE);
                    return -1;
                }
                nexttab = nextarr->u.tab[nextarr->nelem - 1];
                break;

            case 'v':
                e_key_exists_error(ctx, ctx->tpath.tok[i].lineno);
                return -1;

            default: { /* Not found. Let's create an implicit table. */
                int n               = curtab->ntab;
                toml_table_t** base = (toml_table_t**)malloc((n + 1) * sizeof(*base));
                if (0 == base) {
                    e_outofmemory(ctx, FLINE);
                    return -1;
                }
                memcpy(base, curtab->tab, n * sizeof(*base));
                free(curtab->tab);
                curtab->tab = base;

                if (0 == (base[n] = (toml_table_t*)calloc(1, sizeof(*base[n])))) {
                    e_outofmemory(ctx, FLINE);
                    return -1;
                }

                if (0 == (base[n]->key = _strdup(key))) {
                    e_outofmemory(ctx, FLINE);
                    return -1;
                }

                nexttab = curtab->tab[curtab->ntab++];

                /* tabs created by walk_tabpath are considered implicit */
                nexttab->implicit = 1;
            } break;
        }

        /* switch to next tab */
        curtab = nexttab;
    }

    /* save it */
    ctx->curtab = curtab;
    return 0;
}

/* handle lines like [x.y.z] or [[x.y.z]] */
static int parse_select(context_t* ctx) {
    assert(ctx->tok.tok == TOML_TOKEN_LBRACKET);

    /* true if [[ */
    int llb = (ctx->tok.ptr + 1 < ctx->stop && ctx->tok.ptr[1] == '[');
    /* need to detect '[[' on our own because next_token() will skip whitespace,
       and '[ [' would be taken as '[[', which is wrong */

    /* eat [ or [[ */
    if (-1 == next_token(ctx, 1)) {
        /* next_token() already updated ctx->errbuf */
        return -1;
    }

    if (llb) {
        assert(ctx->tok.tok == TOML_TOKEN_LBRACKET);
        if (-1 == next_token(ctx, 1)) {
            /* next_token() already updated ctx->errbuf */
            return -1;
        }
    }

    if (-1 == fill_tabpath(ctx)) {
        /* fill_tabpath() already updated ctx->errbuf */
        return -1;
    }

    /* For [x.y.z] or [[x.y.z]], remove z from tpath */
    token_t z = ctx->tpath.tok[ctx->tpath.top - 1];
    free(ctx->tpath.key[ctx->tpath.top - 1]);
    ctx->tpath.top--;

    /* set up ctx->curtab */
    if (-1 == walk_tabpath(ctx)) {
        /* walk_tabpath() already updated ctx->errbuf */
        return -1;
    }

    if (!llb) {
        /* [x.y.z] -> create z = {} in x.y */
        ctx->curtab = create_keytable_in_table(ctx, ctx->curtab, z);
        if (!ctx->curtab) {
            /* create_keytable_in_table() already updated ctx->errbuf */
            return -1;
        }
    } else {
        /* [[x.y.z]] -> create z = [] in x.y */
        toml_array_t* arr = 0;
        {
            char* zstr = normalize_key(ctx, z);
            if (!zstr) {
                /* normalize_key() already updated ctx->errbuf */
                return -1;
            }

            arr = toml_array_in(ctx->curtab, zstr);
            free(zstr);
        }
        if (!arr) {
            arr = create_keyarray_in_table(ctx, ctx->curtab, z, 't');
            if (!arr) {
                /* create_keyarray_in_table() already updated ctx->errbuf */
                return -1;
            }
        }
        if (arr->kind != 't') {
            e_syntax_error(ctx, z.lineno, "array mismatch");
            return -1;
        }

        /* add to z[] */
        toml_table_t* dest;
        {
            int n = arr->nelem;
            toml_table_t** base = malloc((n + 1) * sizeof(*base));
            if (0 == base) {
                e_outofmemory(ctx, FLINE);
                return -1;
            }
            memcpy(base, arr->u.tab, n * sizeof(*base));
            free(arr->u.tab);
            arr->u.tab = base;

            if (0 == (base[n] = calloc(1, sizeof(*base[n])))) {
                e_outofmemory(ctx, FLINE);
                return -1;
            }

            if (0 == (base[n]->key = _strdup("__anon__"))) {
                e_outofmemory(ctx, FLINE);
                return -1;
            }

            dest = arr->u.tab[arr->nelem++];
        }

        ctx->curtab = dest;
    }

    if (ctx->tok.tok != TOML_TOKEN_RBRACKET) {
        e_syntax_error(ctx, ctx->tok.lineno, "expects ]");
        return -1;
    }
    if (llb) {
        if (!(ctx->tok.ptr + 1 < ctx->stop && ctx->tok.ptr[1] == ']')) {
            e_syntax_error(ctx, ctx->tok.lineno, "expects ]]");
            return -1;
        }
        if (-1 == next_token(ctx, 1)) {
            /* next_token() already updated ctx->errbuf */
            return -1;
        }
    }

    if (-1 == next_token(ctx, 1)) {
        /* next_token() already updated ctx->errbuf */
        return -1;
    }

    if (ctx->tok.tok != TOML_TOKEN_NEWLINE) {
        e_syntax_error(ctx, ctx->tok.lineno, "extra chars after ] or ]]");
        return -1;
    }

    return 0;
}

toml_table_t* toml_parse(char* conf, char* errbuf, int errbufsz) {
    context_t ctx;

    if (errbufsz <= 0)
        errbufsz = 0;
    if (errbufsz > 0)
        errbuf[0] = 0;

    memset(&ctx, 0, sizeof(ctx));
    ctx.start    = conf;
    ctx.stop     = ctx.start + strlen(conf);
    ctx.errbuf   = errbuf;
    ctx.errbufsz = errbufsz;

    /* start with an artificial newline of length 0 */
    ctx.tok.tok    = TOML_TOKEN_NEWLINE;
    ctx.tok.lineno = 1;
    ctx.tok.ptr    = conf;
    ctx.tok.len    = 0;

    /* make a root table */
    if (0 == (ctx.root = calloc(1, sizeof(*ctx.root)))) {
        e_outofmemory(&ctx, FLINE);
        return 0;
    }

    /* set root as default table */
    ctx.curtab = ctx.root;

    /* Scan forward until EOF */
    for (token_t tok = ctx.tok; !tok.eof; tok = ctx.tok) {
        switch (tok.tok) {
            case TOML_TOKEN_NEWLINE:
                if (-1 == next_token(&ctx, 1)) {
                    /* next_token() already updated ctx->errbuf */
                    goto fail;
                }
                break;

            case TOML_TOKEN_STRING:
                if (-1 == parse_keyval(&ctx, ctx.curtab)) {
                    /* parse_keyval() already updated ctx->errbuf */
                    goto fail;
                }

                if (ctx.tok.tok != TOML_TOKEN_NEWLINE) {
                    e_syntax_error(&ctx, ctx.tok.lineno, "extra chars after value");
                    goto fail;
                }

                if (-1 == next_token(&ctx, 1)) {
                    /* next_token() already updated ctx->errbuf */
                    goto fail;
                }
                break;

            case TOML_TOKEN_LBRACKET: /* [ x.y.z ] or [[ x.y.z ]] */
                if (-1 == parse_select(&ctx)) {
                    /* parse_select() already updated ctx->errbuf */
                    goto fail;
                }
                break;

            default:
                e_syntax_error(&ctx, tok.lineno, "syntax error");
                goto fail;
        }
    }

    /* success */
    for (int i = 0; i < ctx.tpath.top; i++)
        free(ctx.tpath.key[i]);
    return ctx.root;

fail:
    for (int i = 0; i < ctx.tpath.top; i++)
        free(ctx.tpath.key[i]);
    toml_free(ctx.root);
    return 0;
}

static void free_kval(toml_keyval_t* p) {
    if (!p)
        return;
    free((void*)p->key);
    free((void*)p->val);
    free(p);
}

static void free_arr(toml_array_t* p) {
    if (!p)
        return;

    free((void*)p->key);
    switch (p->kind) {
        case 'v':
            for (int i = 0; i < p->nelem; i++)
                free(p->u.val[i]);
            free(p->u.val);
            break;

        case 'a':
            for (int i = 0; i < p->nelem; i++)
                free_arr(p->u.arr[i]);
            free(p->u.arr);
            break;

        case 't':
            for (int i = 0; i < p->nelem; i++)
                free_tab(p->u.tab[i]);
            free(p->u.tab);
            break;
    }

    free(p);
}

static void free_tab(toml_table_t* p) {
    int i;

    if (!p)
        return;

    free((void*)p->key);

    for (i = 0; i < p->nkval; i++)
        free_kval(p->kval[i]);
    free(p->kval);

    for (i = 0; i < p->narr; i++)
        free_arr(p->arr[i]);
    free(p->arr);

    for (i = 0; i < p->ntab; i++)
        free_tab(p->tab[i]);
    free(p->tab);

    free(p);
}

void toml_free(toml_table_t* tab) {
    free_tab(tab);
}

static void ret_token(context_t* ctx, tokentype_t tok, int lineno, char* ptr, int len) {
    token_t t;
    t.tok    = tok;
    t.lineno = lineno;
    t.ptr    = ptr;
    t.len    = len;
    t.eof    = 0;
    ctx->tok = t;
}

static void ret_eof(context_t* ctx, int lineno) {
    ret_token(ctx, TOML_TOKEN_NEWLINE, lineno, ctx->stop, 0);
    ctx->tok.eof = 1;
}

/* Scan p for n digits compositing entirely of [0-9] */
static int scan_digits(const char* p, int n) {
    int ret = 0;
    for (; n > 0 && _isdigit(*p); n--, p++) {
        ret = 10 * ret + (*p - '0');
    }
    return n ? -1 : ret;
}

static int scan_date(const char* p, int* YY, int* MM, int* DD) {
    int year, month, day;
    year  = scan_digits(p, 4);
    month = (year >= 0 && p[4] == '-') ? scan_digits(p + 5, 2) : -1;
    day   = (month >= 0 && p[7] == '-') ? scan_digits(p + 8, 2) : -1;
    if (YY)
        *YY = year;
    if (MM)
        *MM = month;
    if (DD)
        *DD = day;
    return (year >= 0 && month >= 0 && day >= 0) ? 0 : -1;
}

static int scan_time(const char* p, int* hh, int* mm, int* ss) {
    int hour, minute, second;
    hour   = scan_digits(p, 2);
    minute = (hour >= 0 && p[2] == ':') ? scan_digits(p + 3, 2) : -1;
    second = (minute >= 0 && p[5] == ':') ? scan_digits(p + 6, 2) : -1;
    if (hh)
        *hh = hour;
    if (mm)
        *mm = minute;
    if (ss)
        *ss = second;
    return (hour >= 0 && minute >= 0 && second >= 0) ? 0 : -1;
}

static int scan_string(context_t* ctx, char* p, int lineno, int dotisspecial) {
    char* orig = p;
    if (0 == strncmp(p, "'''", 3)) {
        p = strstr(p + 3, "'''");
        if (0 == p) {
            e_syntax_error(ctx, lineno, "unterminated triple-s-quote");
            return -1;
        }

        ret_token(ctx, TOML_TOKEN_STRING, lineno, orig, p + 3 - orig);
        return 0;
    }

    if (0 == strncmp(p, "\"\"\"", 3)) {
        int hexreq = 0; /* #hex required */
        int escape = 0;
        int qcnt   = 0; /* count quote */
        for (p += 3; *p && qcnt < 3; p++) {
            if (escape) {
                escape = 0;
                if (strchr("btnfr\"\\", *p))
                    continue;
                if (*p == 'u') {
                    hexreq = 4;
                    continue;
                }
                if (*p == 'U') {
                    hexreq = 8;
                    continue;
                }
                if (p[strspn(p, " \t\r")] == '\n')
                    continue; /* allow for line ending backslash */
                e_syntax_error(ctx, lineno, "bad escape char");
                return -1;
            }
            if (hexreq) {
                hexreq--;
                if (strchr("0123456789ABCDEF", *p))
                    continue;
                e_syntax_error(ctx, lineno, "expect hex char");
                return -1;
            }
            if (*p == '\\') {
                escape = 1;
                continue;
            }
            qcnt = (*p == '"') ? qcnt + 1 : 0;
        }
        if (qcnt != 3) {
            e_syntax_error(ctx, lineno, "unterminated triple-quote");
            return -1;
        }

        ret_token(ctx, TOML_TOKEN_STRING, lineno, orig, p - orig);
        return 0;
    }

    if ('\'' == *p) {
        for (p++; *p && *p != '\n' && *p != '\''; p++)
            ;
        if (*p != '\'') {
            e_syntax_error(ctx, lineno, "unterminated s-quote");
            return -1;
        }

        ret_token(ctx, TOML_TOKEN_STRING, lineno, orig, p + 1 - orig);
        return 0;
    }

    if ('\"' == *p) {
        int hexreq = 0; /* #hex required */
        int escape = 0;
        for (p++; *p; p++) {
            if (escape) {
                escape = 0;
                if (strchr("btnfr\"\\", *p))
                    continue;
                if (*p == 'u') {
                    hexreq = 4;
                    continue;
                }
                if (*p == 'U') {
                    hexreq = 8;
                    continue;
                }
                e_syntax_error(ctx, lineno, "bad escape char");
                return -1;
            }
            if (hexreq) {
                hexreq--;
                if (strchr("0123456789ABCDEF", *p))
                    continue;
                e_syntax_error(ctx, lineno, "expect hex char");
                return -1;
            }
            if (*p == '\\') {
                escape = 1;
                continue;
            }
            if (*p == '\n')
                break;
            if (*p == '"')
                break;
        }
        if (*p != '"') {
            e_syntax_error(ctx, lineno, "unterminated quote");
            return -1;
        }

        ret_token(ctx, TOML_TOKEN_STRING, lineno, orig, p + 1 - orig);
        return 0;
    }

    /* check for timestamp without quotes */
    if (0 == scan_date(p, 0, 0, 0) || 0 == scan_time(p, 0, 0, 0)) {
        /* forward thru the timestamp */
        for (; strchr("0123456789.:+-T Z", _toupper(*p)); p++)
            ;
        /* squeeze out any spaces at end of string */
        for (; p[-1] == ' '; p--)
            ;
        /* tokenize */
        ret_token(ctx, TOML_TOKEN_STRING, lineno, orig, p - orig);
        return 0;
    }

    /* literals */
    for (; *p && *p != '\n'; p++) {
        int ch = *p;
        if (ch == '.' && dotisspecial)
            break;
        if ('A' <= ch && ch <= 'Z')
            continue;
        if ('a' <= ch && ch <= 'z')
            continue;
        if (strchr("0123456789+-_.", ch))
            continue;
        break;
    }

    ret_token(ctx, TOML_TOKEN_STRING, lineno, orig, p - orig);
    return 0;
}

static int next_token(context_t* ctx, int dotisspecial) {
    int lineno = ctx->tok.lineno;
    char* p    = ctx->tok.ptr;
    int i;

    /* eat this tok */
    for (i = 0; i < ctx->tok.len; i++) {
        if (*p++ == '\n')
            lineno++;
    }

    /* make next tok */
    while (p < ctx->stop) {
        /* skip comment. stop just before the \n. */
        if (*p == '#') {
            for (p++; p < ctx->stop && *p != '\n'; p++)
                ;
            continue;
        }

        if (dotisspecial && *p == '.') {
            ret_token(ctx, TOML_TOKEN_DOT, lineno, p, 1);
            return 0;
        }

        switch (*p) {
            case ',':
                ret_token(ctx, TOML_TOKEN_COMMA, lineno, p, 1);
                return 0;
            case '=':
                ret_token(ctx, TOML_TOKEN_EQUAL, lineno, p, 1);
                return 0;
            case '{':
                ret_token(ctx, TOML_TOKEN_LBRACE, lineno, p, 1);
                return 0;
            case '}':
                ret_token(ctx, TOML_TOKEN_RBRACE, lineno, p, 1);
                return 0;
            case '[':
                ret_token(ctx, TOML_TOKEN_LBRACKET, lineno, p, 1);
                return 0;
            case ']':
                ret_token(ctx, TOML_TOKEN_RBRACKET, lineno, p, 1);
                return 0;
            case '\n':
                ret_token(ctx, TOML_TOKEN_NEWLINE, lineno, p, 1);
                return 0;
            case '\r':
            case ' ':
            case '\t':
                /* ignore white spaces */
                p++;
                continue;
        }

        return scan_string(ctx, p, lineno, dotisspecial);
    }

    ret_eof(ctx, lineno);
    return 0;
}

const char* toml_key_in(const toml_table_t* tab, int keyidx) {
    if (keyidx < tab->nkval)
        return tab->kval[keyidx]->key;

    keyidx -= tab->nkval;
    if (keyidx < tab->narr)
        return tab->arr[keyidx]->key;

    keyidx -= tab->narr;
    if (keyidx < tab->ntab)
        return tab->tab[keyidx]->key;

    return 0;
}

toml_raw_t toml_raw_in(const toml_table_t* tab, const char* key) {
    int i;
    for (i = 0; i < tab->nkval; i++) {
        if (0 == strcmp(key, tab->kval[i]->key))
            return tab->kval[i]->val;
    }
    return 0;
}

toml_array_t* toml_array_in(const toml_table_t* tab, const char* key) {
    int i;
    for (i = 0; i < tab->narr; i++) {
        if (0 == strcmp(key, tab->arr[i]->key))
            return tab->arr[i];
    }
    return 0;
}

toml_table_t* toml_table_in(const toml_table_t* tab, const char* key) {
    int i;
    for (i = 0; i < tab->ntab; i++) {
        if (0 == strcmp(key, tab->tab[i]->key))
            return tab->tab[i];
    }
    return 0;
}

toml_raw_t toml_raw_at(const toml_array_t* arr, int idx) {
    if (arr->kind != 'v')
        return 0;
    if (!(0 <= idx && idx < arr->nelem))
        return 0;
    return arr->u.val[idx];
}

char toml_array_kind(const toml_array_t* arr) {
    return arr->kind;
}

char toml_array_type(const toml_array_t* arr) {
    if (arr->kind != 'v')
        return 0;

    if (arr->nelem == 0)
        return 0;

    return arr->type;
}

int toml_array_nelem(const toml_array_t* arr) {
    return arr->nelem;
}

const char* toml_array_key(const toml_array_t* arr) {
    return arr ? arr->key : (const char*)NULL;
}

int toml_table_nkval(const toml_table_t* tab) {
    return tab->nkval;
}

int toml_table_narr(const toml_table_t* tab) {
    return tab->narr;
}

int toml_table_ntab(const toml_table_t* tab) {
    return tab->ntab;
}

const char* toml_table_key(const toml_table_t* tab) {
    return tab ? tab->key : (const char*)NULL;
}

toml_array_t* toml_array_at(const toml_array_t* arr, int idx) {
    if (arr->kind != 'a')
        return 0;
    if (!(0 <= idx && idx < arr->nelem))
        return 0;
    return arr->u.arr[idx];
}

toml_table_t* toml_table_at(const toml_array_t* arr, int idx) {
    if (arr->kind != 't')
        return 0;
    if (!(0 <= idx && idx < arr->nelem))
        return 0;
    return arr->u.tab[idx];
}

int toml_rtots(toml_raw_t src_, toml_timestamp_t* ret) {
    if (!src_)
        return -1;

    const char* p       = src_;
    int must_parse_time = 0;

    memset(ret, 0, sizeof(*ret));

    int* year     = &ret->__buffer.year;
    int* month    = &ret->__buffer.month;
    int* day      = &ret->__buffer.day;
    int* hour     = &ret->__buffer.hour;
    int* minute   = &ret->__buffer.minute;
    int* second   = &ret->__buffer.second;
    int* millisec = &ret->__buffer.millisec;

    /* parse date YYYY-MM-DD */
    if (0 == scan_date(p, year, month, day)) {
        ret->year  = year;
        ret->month = month;
        ret->day   = day;

        p += 10;
        if (*p) {
            /* parse the T or space separator */
            if (*p != 'T' && *p != ' ')
                return -1;
            must_parse_time = 1;
            p++;
        }
    }

    /* parse time HH:MM:SS */
    if (0 == scan_time(p, hour, minute, second)) {
        ret->hour   = hour;
        ret->minute = minute;
        ret->second = second;

        /* optionally, parse millisec */
        p += 8;
        if (*p == '.') {
            char* qq;
            p++;
            /* FIXME: Graphene's strtol() implementation doesn't report errors */
            *millisec = strtol(p, &qq, 0);
            while (*millisec > 999) {
                *millisec /= 10;
            }

            ret->millisec = millisec;
            p             = qq;
        }

        if (*p) {
            /* parse and copy Z */
            char* z = ret->__buffer.z;
            ret->z  = z;
            if (*p == 'Z' || *p == 'z') {
                *z++ = 'Z';
                p++;
                *z = 0;

            } else if (*p == '+' || *p == '-') {
                *z++ = *p++;

                if (!(_isdigit(p[0]) && _isdigit(p[1])))
                    return -1;
                *z++ = *p++;
                *z++ = *p++;

                if (*p == ':') {
                    *z++ = *p++;

                    if (!(_isdigit(p[0]) && _isdigit(p[1])))
                        return -1;
                    *z++ = *p++;
                    *z++ = *p++;
                }

                *z = 0;
            }
        }
    }
    if (*p != 0)
        return -1;

    if (must_parse_time && !ret->hour)
        return -1;

    return 0;
}

/* Raw to boolean */
int toml_rtob(toml_raw_t src, int* ret_) {
    if (!src)
        return -1;
    int dummy;
    int* ret = ret_ ? ret_ : &dummy;

    if (0 == strcmp(src, "true")) {
        *ret = 1;
        return 0;
    }
    if (0 == strcmp(src, "false")) {
        *ret = 0;
        return 0;
    }
    return -1;
}

/* Raw to integer */
int toml_rtoi(toml_raw_t src, int64_t* ret_) {
    if (!src)
        return -1;

    char buf[100];
    char* p       = buf;
    char* q       = p + sizeof(buf);
    const char* s = src;
    int base      = 0;
    int64_t dummy;
    int64_t* ret = ret_ ? ret_ : &dummy;

    /* allow +/- */
    if (s[0] == '+' || s[0] == '-')
        *p++ = *s++;

    /* disallow +_100 */
    if (s[0] == '_')
        return -1;

    /* if 0 ... */
    if ('0' == s[0]) {
        switch (s[1]) {
            case 'x':
                base = 16;
                s += 2;
                break;
            case 'o':
                base = 8;
                s += 2;
                break;
            case 'b':
                base = 2;
                s += 2;
                break;
            case '\0':
                return *ret = 0, 0;
            default:
                /* ensure no other digits after it */
                if (s[1])
                    return -1;
        }
    }

    /* just strip underscores and pass to strtoll */
    while (*s && p < q) {
        int ch = *s++;
        switch (ch) {
            case '_':
                /* disallow '__' */
                if (s[0] == '_')
                    return -1;
                continue; /* skip _ */
            default:
                break;
        }
        *p++ = ch;
    }
    if (*s || p == q)
        return -1;

    /* last char cannot be '_' */
    if (s[-1] == '_')
        return -1;

    /* cap with NUL */
    *p = 0;

    /* Run strtoll on buf to get the integer */
    char* endp;
#ifdef __LP64__
	/* long int == long long int on targets with data model LP64, so can reuse strtol() */
    /* FIXME: Graphene's strtol() implementation doesn't report errors */
    *ret  = strtol(buf, &endp, base);
#else
    *ret  = strtoll(buf, &endp, base);
#endif
    return *endp ? -1 : 0;
}

int toml_rtod_ex(toml_raw_t src, double* ret_, char* buf, int buflen) {
    if (!src)
        return -1;

#if 1
    /* FIXME: Graphene doesn't have strtod() so disallow doubles for now */
    __UNUSED(ret_);
    __UNUSED(buf);
    __UNUSED(buflen);
    return -1;
#else
    char* p       = buf;
    char* q       = p + buflen;
    const char* s = src;
    double dummy;
    double* ret = ret_ ? ret_ : &dummy;

    /* allow +/- */
    if (s[0] == '+' || s[0] == '-')
        *p++ = *s++;

    /* disallow +_1.00 */
    if (s[0] == '_')
        return -1;

    /* disallow +.99 */
    if (s[0] == '.')
        return -1;

    /* zero must be followed by . or 'e', or NUL */
    if (s[0] == '0' && s[1] && !strchr("eE.", s[1]))
        return -1;

    /* just strip underscores and pass to strtod */
    while (*s && p < q) {
        int ch = *s++;
        switch (ch) {
            case '.':
                if (s[-2] == '_')
                    return -1;
                if (s[0] == '_')
                    return -1;
                break;
            case '_':
                // disallow '__'
                if (s[0] == '_')
                    return -1;
                continue; /* skip _ */
            default:
                break;
        }
        *p++ = ch;
    }
    if (*s || p == q)
        return -1; /* reached end of string or buffer is full? */

    /* last char cannot be '_' */
    if (s[-1] == '_')
        return -1;

    if (p != buf && p[-1] == '.')
        return -1; /* no trailing zero */

    /* cap with NUL */
    *p = 0;

    /* Run strtod on buf to get the value */
    char* endp;
    /* FIXME: Graphene's strtod() implementation doesn't report errors */
    *ret  = strtod(buf, &endp);
    return *endp ? -1 : 0;
#endif
}

int toml_rtod(toml_raw_t src, double* ret_) {
    char buf[100];
    return toml_rtod_ex(src, ret_, buf, sizeof(buf));
}

int toml_rtos(toml_raw_t src, char** ret) {
    int multiline = 0;
    const char* sp;
    const char* sq;

    *ret = 0;
    if (!src)
        return -1;

    int qchar  = src[0];
    int srclen = strlen(src);
    if (!(qchar == '\'' || qchar == '"')) {
        return -1;
    }

    /* triple quotes? */
    if (qchar == src[1] && qchar == src[2]) {
        multiline = 1;
        sp        = src + 3;
        sq        = src + srclen - 3;
        /* last 3 chars in src must be qchar */
        if (!(sp <= sq && sq[0] == qchar && sq[1] == qchar && sq[2] == qchar))
            return -1;

        /* skip new line immediate after qchar */
        if (sp[0] == '\n')
            sp++;
        else if (sp[0] == '\r' && sp[1] == '\n')
            sp += 2;

    } else {
        sp = src + 1;
        sq = src + srclen - 1;
        /* last char in src must be qchar */
        if (!(sp <= sq && *sq == qchar))
            return -1;
    }

    if (qchar == '\'') {
        *ret = norm_lit_str(sp, sq - sp, multiline, 0, 0);
    } else {
        *ret = norm_basic_str(sp, sq - sp, multiline, 0, 0);
    }

    return *ret ? 0 : -1;
}
