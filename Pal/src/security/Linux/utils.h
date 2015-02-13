/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#ifndef __UTILS_H__
#define __UTILS_H__

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

#include "api.h"

#define PAL_LOADER  XSTRINGIFY(PAL_LOADER_PATH)

#ifdef __x86_64__
# include "sysdep-x86_64.h"
#endif

#undef IS_ERR
#undef IS_ERR_P
#undef ERRNO
#undef ERRNO_P

#define IS_ERR INTERNAL_SYSCALL_ERROR
#define IS_ERR_P INTERNAL_SYSCALL_ERROR_P
#define ERRNO INTERNAL_SYSCALL_ERRNO
#define ERRNO_P INTERNAL_SYSCALL_ERRNO_P

int printf (const char * fmt, ...);
int snprintf (char * buf, size_t n, const char * fmt, ...);

void * malloc (int size);
void free (void * mem);

extern unsigned long pagesize;
extern unsigned long pageshift;
extern unsigned long pagemask;

static inline int is_file_uri (const char * uri)
{
    if (uri[0] == 'f' && uri[1] == 'i' && uri[2] == 'l' && uri[3] == 'e' &&
        uri[4] == ':')
        return 1;

    return 0;
}

static inline void fast_strcpy (char * d, const char * s, int len)
{
    while (len) {
        *d = *s;
        d++;
        s++;
        len--;
    }

    *d = 0;
}

static inline const char * file_uri_to_path (const char * uri, int len)
{
    char * path;

    if (len == 5) {
        path = malloc(2);
        if (!path)
            return NULL;

        path[0] = '.';
        path[1] = 0;
        return path;
    }

    path = malloc(len - 4);
    if (!path)
        return NULL;

    fast_strcpy(path, uri + 5, len - 5);
    return path;
}

#endif /* __UTILS_H__ */
