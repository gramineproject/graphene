/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#ifndef __INTERNAL_H__
#define __INTERNAL_H__

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

#include "api.h"

#define PAL_LOADER  XSTRINGIFY(PAL_LOADER_PATH)

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

extern char __text_start, __text_end, __data_start, __data_end;
#define TEXT_START (void *) (&__text_start)
#define TEXT_END   (void *) (&__text_end)
#define DATA_START (void *) (&__data_start)
#define DATA_END   (void *) (&__data_end)

extern char __pool_start, __pool_end;

extern unsigned int reference_monitor;

int sys_open(const char * path, int flags, int mode);

#endif /* __INTERNAL_H__ */
