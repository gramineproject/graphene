/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2014 OSCAR lab, Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#ifndef API_H
#define API_H

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

size_t strnlen (const char *str, size_t maxlen);
size_t strlen (const char *str);

long strtol (const char *s, char **endptr, int base);
int atoi (const char *nptr);
long int atol (const char *nptr);

char * strchr (const char *s, int c_in);

void * memcpy (void *dstpp, const void *srcpp, size_t len);
void * memmove (void *dstpp, void *srcpp, size_t len);
void * memset (void *dstpp, int c, size_t len);
int memcmp (const void *s1, const void *s2, size_t len);

void fprintfmt (void (*_fputch)(void *, int, void *), void * f, void * putdat,
                const char * fmt, ...);

void vfprintfmt (void (*_fputch)(void *, int, void *), void * f, void * putdat,
                 const char * fmt, va_list ap);

int inet_pton(int af, const char *src, void *dst);

uint32_t __htonl (uint32_t x);
uint32_t __ntohl (uint32_t x);
uint16_t __htons (uint16_t x);
uint16_t __ntohs (uint16_t x);

extern const char * const * sys_errlist_internal;

#define __alloca __builtin_alloca

#define XSTRINGIFY(x) STRINGIFY(x)
#define STRINGIFY(x) #x

#include <linux_list.h>

struct config_store {
    struct list_head    root, entries;
    void *              raw_data;
    size_t              raw_size;
    void *              (*malloc) (int);
    void                (*free) (void *);
};

int read_config (struct config_store * store,
                 int (*filter) (const char * key, int ken),
                 const char ** errstring);
int free_config (struct config_store * store);
int copy_config (struct config_store * store, struct config_store * new_store);
int write_config (void * f, size_t (*write) (void *, void *, size_t),
                  struct config_store * store);
int get_config (struct config_store * cfg, const char * key,
                char * val_buf, size_t size);
int get_config_entries (struct config_store * cfg, const char * key,
                        char * key_buf, size_t size);
int set_config (struct config_store * cfg, const char * key, const char * val);

#define CONFIG_MAX      256

#endif /* API_H */
