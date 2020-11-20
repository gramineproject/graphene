/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#ifndef API_H
#define API_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "assert.h"
#include "list.h"
#include "toml.h"

/* WARNING: this declaration may conflict with some header files */
#ifndef ssize_t
typedef ptrdiff_t ssize_t;
#endif

/* Macros */

#ifndef MIN
#define MIN(a, b)               \
    ({                          \
        __typeof__(a) _a = (a); \
        __typeof__(b) _b = (b); \
        _a < _b ? _a : _b;      \
    })
#endif
#ifndef MAX
#define MAX(a, b)               \
    ({                          \
        __typeof__(a) _a = (a); \
        __typeof__(b) _b = (b); \
        _a > _b ? _a : _b;      \
    })
#endif

#define SATURATED_ADD(a, b, limit)                                    \
    ({                                                                \
        __typeof__(a) _a = (a);                                       \
        __typeof__(b) _b = (b);                                       \
        __typeof__(limit) _limit = (limit);                           \
        _b > _limit ? _limit : (_a > _limit - _b ? _limit : _a + _b); \
    })

#define SATURATED_SUB(a, b, limit)                                    \
    ({                                                                \
        __typeof__(a) _a = (a);                                       \
        __typeof__(b) _b = (b);                                       \
        __typeof__(limit) _limit = (limit);                           \
        _a < _limit ? _limit : (_b > _a - _limit ? _limit : _a - _b); \
    })

#define SATURATED_P_ADD(ptr_a, b, limit) \
    ((__typeof__(ptr_a))SATURATED_ADD((uintptr_t)(ptr_a), (uintptr_t)(b), (uintptr_t)(limit)))

#define SATURATED_P_SUB(ptr_a, b, limit) \
    ((__typeof__(ptr_a))SATURATED_SUB((uintptr_t)(ptr_a), (uintptr_t)(b), (uintptr_t)(limit)))

#define IS_POWER_OF_2(x)          \
    ({                            \
        assert((x) != 0);         \
        (((x) & ((x) - 1)) == 0); \
    })

#define DIV_ROUND_UP(n,d)               (((n) + (d) - 1) / (d))

#define BITS_IN_BYTE                    8
#define BITS_IN_TYPE(type)              (sizeof(type) * BITS_IN_BYTE)
#define BITS_TO_LONGS(nr)               DIV_ROUND_UP(nr, BITS_IN_TYPE(long))
/* Note: This macro is not intended for use when nbits == BITS_IN_TYPE(type) */
#define SET_HIGHEST_N_BITS(type, nbits) (~(((uint64_t)1 << (BITS_IN_TYPE(type) - (nbits))) - 1))

#define IS_ALIGNED(val, alignment)     ((val) % (alignment) == 0)
#define ALIGN_DOWN(val, alignment)     ((val) - (val) % (alignment))
#define ALIGN_UP(val, alignment)       ALIGN_DOWN((val) + (alignment) - 1, alignment)
#define IS_ALIGNED_PTR(val, alignment) IS_ALIGNED((uintptr_t)(val), alignment)
#define ALIGN_DOWN_PTR(ptr, alignment) ((__typeof__(ptr))(ALIGN_DOWN((uintptr_t)(ptr), alignment)))
#define ALIGN_UP_PTR(ptr, alignment)   ((__typeof__(ptr))(ALIGN_UP((uintptr_t)(ptr), alignment)))

/* Useful only when the alignment is a power of two, but when that's not known compile-time. */
#define IS_ALIGNED_POW2(val, alignment) (((val) & ((alignment) - 1)) == 0)
#define ALIGN_DOWN_POW2(val, alignment) \
    ((val) - ((val) & ((alignment) - 1))) // `~` doesn't work if `alignment` is of a smaller type
                                          // than `val` and unsigned.
#define ALIGN_UP_POW2(val, alignment)       ALIGN_DOWN_POW2((val) + (alignment) - 1, alignment)
#define IS_ALIGNED_PTR_POW2(val, alignment) IS_ALIGNED_POW2((uintptr_t)(val), alignment)
#define ALIGN_DOWN_PTR_POW2(ptr, alignment) \
    ((__typeof__(ptr))(ALIGN_DOWN_POW2((uintptr_t)(ptr), alignment)))
#define ALIGN_UP_PTR_POW2(ptr, alignment) \
    ((__typeof__(ptr))(ALIGN_UP_POW2((uintptr_t)(ptr), alignment)))

#define SAME_TYPE(a, b)       __builtin_types_compatible_p(__typeof__(a), __typeof__(b))
#define IS_STATIC_ARRAY(a)    (!SAME_TYPE(a, &*(a)))
#define FORCE_STATIC_ARRAY(a) sizeof(int[IS_STATIC_ARRAY(a) - 1]) // evaluates to 0

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (FORCE_STATIC_ARRAY(a) + sizeof(a) / sizeof(a[0]))
#endif

#define DEBUG_BREAK()               \
    do {                            \
        __asm__ volatile("int $3"); \
    } while (0)

#ifndef container_of
/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:    the pointer to the member.
 * @type:   the type of the container struct this is embedded in.
 * @member: the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ((type*)((char*)(ptr) - offsetof(type, member)))
#endif

#define __alloca __builtin_alloca

#define XSTRINGIFY(x) STRINGIFY(x)
#define STRINGIFY(x)  #x

/* fail build if str is not a static string */
#define FORCE_LITERAL_CSTR(str) ("" str "")

#define __UNUSED(x) \
    do {            \
        (void)(x);  \
    } while (0)
#define static_strlen(str) (ARRAY_SIZE(FORCE_LITERAL_CSTR(str)) - 1)

/* LibC functions */

/* LibC string functions */
size_t strnlen(const char* str, size_t maxlen);
size_t strlen(const char* str);
int strncmp(const char* lhs, const char* rhs, size_t maxlen);
int strcmp(const char* lhs, const char* rhs);

long strtol(const char* s, char** endptr, int base);
long long strtoll(const char* s, char** endptr, int base);
int atoi(const char* nptr);
long int atol(const char* nptr);

int islower(int c);
int toupper(int c);
int isalpha(int c);
int isdigit(int c);
int isalnum(int c);

char* strchr(const char* s, int c_in);
char* strstr(const char* haystack, const char* needle);
size_t strspn(const char* s, const char* c);

void* memcpy(void* restrict dest, const void* restrict src, size_t count);
void* memmove(void* dest, const void* src, size_t count);
void* memset(void* dest, int ch, size_t count);
int memcmp(const void* lhs, const void* rhs, size_t count);

bool strstartswith(const char* str, const char* prefix);
bool strendswith(const char* str, const char* suffix);
char* strdup(const char* str);
char* alloc_substr(const char* start, size_t len);
char* alloc_concat(const char* a, size_t a_len, const char* b, size_t b_len);
char* alloc_concat3(const char* a, size_t a_len, const char* b, size_t b_len,
                    const char* c, size_t c_len);

/* Libc memory allocation functions */
void* malloc(size_t size);
void free(void* ptr);
void* calloc(size_t nmemb, size_t size);

/* copy static string and return the address of the NUL byte (NULL if the dest
 * is not large enough).*/
#define strcpy_static(var, str, max)                                  \
    (static_strlen(str) + 1 > (max)                                   \
     ? NULL                                                           \
     : memcpy(var, str, static_strlen(str) + 1) + static_strlen(str))

/* Copy a fixed size array. */
#define COPY_ARRAY(dst, src)                                                   \
    do {                                                                       \
        /* Using pointers because otherwise the compiler would try to allocate \
         * memory for the fixed size arrays and complain about invalid         \
         * initializers.                                                       \
         */                                                                    \
        __typeof__(src)* _s = &(src);                                          \
        __typeof__(dst)* _d = &(dst);                                          \
                                                                               \
        static_assert(SAME_TYPE((*_s)[0], (*_d)[0]), "types must match");      \
        static_assert(ARRAY_SIZE(*_s) == ARRAY_SIZE(*_d), "sizes must match"); \
                                                                               \
        memcpy(*_d, *_s, sizeof(*_d));                                         \
    } while (0)

#define COMPILER_BARRIER() ({ __asm__ __volatile__("" ::: "memory"); })

/* Idea taken from: https://elixir.bootlin.com/linux/v5.6/source/include/linux/compiler.h */
#define READ_ONCE(x)                            \
    ({                                          \
        __typeof__(x) _y;                       \
        COMPILER_BARRIER();                     \
        __builtin_memcpy(&_y, &(x), sizeof(x)); \
        COMPILER_BARRIER();                     \
        _y;                                     \
    })

#define WRITE_ONCE(x, y)                        \
    ({                                          \
        __typeof__(x) _y = (__typeof__(x))(y);  \
        COMPILER_BARRIER();                     \
        __builtin_memcpy(&(x), &_y, sizeof(x)); \
        COMPILER_BARRIER();                     \
        _y;                                     \
    })

/* Libc printf functions. stdio.h/stdarg.h. */
void fprintfmt(int (*_fputch)(void*, int, void*), void* f, void* putdat, const char* fmt, ...)
    __attribute__((format(printf, 4, 5)));

void vfprintfmt(int (*_fputch)(void*, int, void*), void* f, void* putdat, const char* fmt,
                va_list ap) __attribute__((format(printf, 4, 0)));

int vsnprintf(char* buf, size_t n, const char* fmt, va_list ap);
int snprintf(char* buf, size_t n, const char* fmt, ...) __attribute__((format(printf, 3, 4)));

/* Miscelleneous */

int inet_pton4(const char* src, size_t len, void* dst);
int inet_pton6(const char* src, size_t len, void* dst);

uint32_t __htonl(uint32_t x);
uint32_t __ntohl(uint32_t x);
uint16_t __htons(uint16_t x);
uint16_t __ntohs(uint16_t x);

extern const char* const* sys_errlist_internal;

/* Graphene functions */

int get_norm_path(const char* path, char* buf, size_t* size);
int get_base_name(const char* path, char* buf, size_t* size);

/*!
 * \brief Parse a size (number with optional "G"/"M"/"K" suffix) into an unsigned long.
 *
 * \param str A string containing a non-negative number. The string may end with "G"/"g" suffix
 *            denoting value in GBs, "M"/"m" for MBs, or "K"/"k" for KBs.
 *
 * By default the number should be decimal, but if it starts with 0x it is parsed as hexadecimal
 * and if it otherwise starts with 0, it is parsed as octal. Function returns -1 if string cannot
 * be parsed into a size (e.g., suffix is wrong).
 */
int64_t parse_size_str(const char* str);

/*!
 * \brief Find an integer key-value in TOML manifest.
 *
 * \param root       Root table of the TOML manifest.
 * \param key        Dotted key (e.g. "loader.insecure__use_cmdline_argv").
 * \param defaultval `retval` is set to this value if not found in the manifest.
 * \param retval     Pointer to output integer.
 *
 * Returns 0 if there were no errors (but value may have not been found in manifest and was set to
 * default one) or -1 if there were errors during conversion to int.
 */
int toml_int_in(const toml_table_t* root, const char* key, int64_t defaultval, int64_t* retval);

/*!
 * \brief Find a string key-value in TOML manifest.
 *
 * \param root      Root table of the TOML manifest.
 * \param key       Dotted key (e.g. "fs.mount.lib1.type").
 * \param retval    Pointer to output string.
 *
 * Returns 0 if there were no errors (but value may have not been found in manifest and was set to
 * NULL) or -1 if there were errors during conversion to string.
 */
int toml_string_in(const toml_table_t* root, const char* key, char** retval);

/*!
 * \brief Find a "size" string key-value in TOML manifest (parsed via `parse_size_str()`).
 *
 * \param root       Root table of the TOML manifest.
 * \param key        Dotted key (e.g. "sys.stack.size").
 * \param defaultval `retval` is set to this value if not found in the manifest.
 * \param retval     Pointer to output integer.
 *
 * Returns 0 if there were no errors (but value may have not been found in manifest and was set to
 * default one) or -1 if there were errors during conversion to "size" string.
 */
int toml_sizestring_in(const toml_table_t* root, const char* key, uint64_t defaultval,
                       uint64_t* retval);

#define URI_PREFIX_SEPARATOR ":"

#define URI_TYPE_DIR      "dir"
#define URI_TYPE_TCP      "tcp"
#define URI_TYPE_TCP_SRV  "tcp.srv"
#define URI_TYPE_UDP      "udp"
#define URI_TYPE_UDP_SRV  "udp.srv"
#define URI_TYPE_PIPE     "pipe"
#define URI_TYPE_PIPE_SRV "pipe.srv"
#define URI_TYPE_DEV      "dev"
#define URI_TYPE_EVENTFD  "eventfd"
#define URI_TYPE_FILE     "file"

#define URI_PREFIX_DIR      URI_TYPE_DIR URI_PREFIX_SEPARATOR
#define URI_PREFIX_TCP      URI_TYPE_TCP URI_PREFIX_SEPARATOR
#define URI_PREFIX_TCP_SRV  URI_TYPE_TCP_SRV URI_PREFIX_SEPARATOR
#define URI_PREFIX_UDP      URI_TYPE_UDP URI_PREFIX_SEPARATOR
#define URI_PREFIX_UDP_SRV  URI_TYPE_UDP_SRV URI_PREFIX_SEPARATOR
#define URI_PREFIX_PIPE     URI_TYPE_PIPE URI_PREFIX_SEPARATOR
#define URI_PREFIX_PIPE_SRV URI_TYPE_PIPE_SRV URI_PREFIX_SEPARATOR
#define URI_PREFIX_DEV      URI_TYPE_DEV URI_PREFIX_SEPARATOR
#define URI_PREFIX_EVENTFD  URI_TYPE_EVENTFD URI_PREFIX_SEPARATOR
#define URI_PREFIX_FILE     URI_TYPE_FILE URI_PREFIX_SEPARATOR

#define URI_PREFIX_FILE_LEN (static_strlen(URI_PREFIX_FILE))

#ifdef __x86_64__
static inline bool __range_not_ok(uintptr_t addr, size_t size) {
    addr += size;
    if (addr < size) {
        /* pointer arithmetic overflow, this check is x86-64 specific */
        return true;
    }
    return false;
}

/* Check if pointer to memory region is valid. Return true if the memory
 * region may be valid, false if it is definitely invalid. */
static inline bool access_ok(const volatile void* addr, size_t size) {
    return !__range_not_ok((uintptr_t)addr, size);
}

#else
#error "Unsupported architecture"
#endif /* __x86_64__ */

#endif /* API_H */
