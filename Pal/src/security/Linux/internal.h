#ifndef __INTERNAL_H__
#define __INTERNAL_H__

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

#include "api.h"

/* RUNTIME_FILE() is defined in pal_internal.h, and including pal_internal.h
 * causes compile issue. So PAL_LOADER is defined without RUNTIME_FILE
 * as workaround. */
#define PAL_LOADER  XSTRINGIFY(RUNTIME_DIR) "/pal-Linux"

#ifdef __x86_64__
# include "sysdep-x86_64.h"
#else
# error "unsupported architecture"
#endif

#define IS_ERR INTERNAL_SYSCALL_ERROR
#define IS_ERR_P INTERNAL_SYSCALL_ERROR_P
#define ERRNO INTERNAL_SYSCALL_ERRNO
#define ERRNO_P INTERNAL_SYSCALL_ERRNO_P

int printf (const char * fmt, ...);
void * malloc (size_t size);
void free (void * mem);

#endif /* __INTERNAL_H__ */
