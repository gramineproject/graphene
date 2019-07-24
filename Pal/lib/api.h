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

#ifndef API_H
#define API_H

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

/* WARNING: this declaration may conflict with some header files */
#ifndef ssize_t
typedef ptrdiff_t ssize_t;
#endif

/* Macros */

#ifndef likely
# define likely(x)	__builtin_expect((!!(x)),1)
#endif
#ifndef unlikely
# define unlikely(x)	__builtin_expect((!!(x)),0)
#endif

#ifndef MIN
#define MIN(a,b) \
   ({ __typeof__(a) _a = (a); \
      __typeof__(b) _b = (b); \
      _a < _b ? _a : _b; })
#endif
#ifndef MAX
#define MAX(a,b) \
   ({ __typeof__(a) _a = (a); \
      __typeof__(b) _b = (b); \
      _a > _b ? _a : _b; })
#endif

#define ALIGN_DOWN_PTR(ptr, size) \
    ((__typeof__(ptr)) (((uintptr_t)(ptr)) & -(size)))
#define ALIGN_UP_PTR(ptr, size) \
    ((__typeof__(ptr)) ALIGN_DOWN_PTR((uintptr_t)(ptr) + ((size) - 1), (size)))

#ifndef container_of
/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:    the pointer to the member.
 * @type:   the type of the container struct this is embedded in.
 * @member: the name of the member within the struct.
 *
 */
# define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))
#endif

#define __alloca __builtin_alloca

#define XSTRINGIFY(x) STRINGIFY(x)
#define STRINGIFY(x) #x

#define static_strlen(str) (sizeof(str) - 1)

/* Turning off unused-parameter warning for keeping function signatures */
#define __UNUSED(x) do { (void)(x); } while (0)

/* Libc functions */

/* Libc String functions string.h/stdlib.h */
size_t strnlen (const char *str, size_t maxlen);
size_t strlen (const char *str);

long strtol (const char *s, char **endptr, int base);
int atoi (const char *nptr);
long int atol (const char *nptr);

char * strchr (const char *s, int c_in);

void * memcpy (void *dstpp, const void *srcpp, size_t len);
void * memmove (void *dstpp, const void *srcpp, size_t len);
void * memset (void *dstpp, int c, size_t len);
int memcmp (const void *s1, const void *s2, size_t len);

/* Libc memory allocation functions. stdlib.h. */
void *malloc(size_t size);
void free(void *ptr);
void *calloc(size_t nmemb, size_t size);

/* Some useful macro */
/* force failure if str is not a static string */
#define force_static(str)   ("" str "")

/* check if the var is exactly the same as the static string */
#define strcmp_static(var, str) \
    (!memcmp((var), force_static(str), static_strlen(force_static(str)) + 1))

/* check if the var starts with the static string */
#define strpartcmp_static(var, str) \
    (!memcmp((var), force_static(str), static_strlen(force_static(str))))

/* copy static string and return the address of the null end (null if the dest
 * is not large enough).*/
#define strcpy_static(var, str, max)                                          \
    (static_strlen(force_static(str)) + 1 > (max) ? NULL :                    \
     memcpy((var), force_static(str), static_strlen(force_static(str)) + 1) + \
     static_strlen(force_static(str)))

/* Copy a fixed size array. */
#define COPY_ARRAY(dst, src)                                                    \
    do {                                                                        \
        /* Using pointers because otherwise the compiler would try to allocate  \
         * memory for the fixed size arrays and complain about invalid          \
         * initializers.                                                        \
         */                                                                     \
        __typeof__(src)* _s = &(src);                                           \
        __typeof__(dst)* _d = &(dst);                                           \
                                                                                \
        __typeof__((*_s)[0]) _s2[sizeof(*_s)/sizeof((*_s)[0])];                 \
        __typeof__((*_d)[0]) _d2[sizeof(*_d)/sizeof((*_d)[0])];                 \
                                                                                \
        /* Causes a compiler warning if the array types mismatch. */            \
        (void) (_s == _d);                                                      \
                                                                                \
        /* Causes a compiler warning if passed arrays are not fixed size        \
         * arrays.                                                              \
         */                                                                     \
        (void) (_s == &_s2);                                                    \
        (void) (_d == &_d2);                                                    \
                                                                                \
        /* Double check sizes. */                                               \
        _Static_assert(sizeof(*_s) == sizeof(*_d), "sizes don't match");        \
                                                                                \
        memcpy(*_d, *_s, sizeof(*_d));                                          \
    } while (0)

/* Libc printf functions. stdio.h/stdarg.h. */
void fprintfmt (int (*_fputch)(void *, int, void *), void * f, void * putdat,
                const char * fmt, ...) __attribute__((format(printf, 4, 5)));

void vfprintfmt (int (*_fputch)(void *, int, void *), void * f, void * putdat,
                 const char * fmt, va_list ap) __attribute__((format(printf, 4, 0)));

int snprintf (char * buf, int n, const char * fmt, ...) __attribute__((format(printf, 3, 4)));

/* Miscelleneous */

int inet_pton4 (const char *src, size_t len, void *dst);
int inet_pton6 (const char *src, size_t len, void *dst);

uint32_t __htonl (uint32_t x);
uint32_t __ntohl (uint32_t x);
uint16_t __htons (uint16_t x);
uint16_t __ntohs (uint16_t x);

extern const char * const * sys_errlist_internal;

/* Graphene functions */

int get_norm_path (const char * path, char * buf, int offset, int size);

int get_base_name (const char * path, char * buf, int size);

/* Loading configs / manifests */

#include <list.h>

struct config;
DEFINE_LISTP(config);
struct config_store {
    LISTP_TYPE(config) root;
    LISTP_TYPE(config) entries;
    void *           raw_data;
    int              raw_size;
    void *           (*malloc) (size_t);
    void             (*free) (void *);
};

int read_config (struct config_store * store, int (*filter) (const char *, int),
                 const char ** errstring);
int free_config (struct config_store * store);
int copy_config (struct config_store * store, struct config_store * new_store);
int write_config (void * file, int (*write) (void *, void *, int),
                  struct config_store * store);
ssize_t get_config (struct config_store * cfg, const char * key,
                    char * val_buf, size_t buf_size);
int get_config_entries (struct config_store * cfg, const char * key,
                        char * key_buf, size_t key_bufsize);
ssize_t get_config_entries_size (struct config_store * cfg, const char * key);
int set_config (struct config_store * cfg, const char * key, const char * val);

#define CONFIG_MAX      4096

#endif /* API_H */
