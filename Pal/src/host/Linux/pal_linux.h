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

#ifndef PAL_LINUX_H
#define PAL_LINUX_H

#include "pal_defs.h"
#include "pal_linux_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux_error.h"

#define PAL_LOADER RUNTIME_FILE("pal-Linux")

#include <sys/syscall.h>
#include <sigset.h>

#ifdef __x86_64__
# include "sysdep-x86_64.h"
#endif

#define IS_ERR INTERNAL_SYSCALL_ERROR
#define IS_ERR_P INTERNAL_SYSCALL_ERROR_P
#define ERRNO INTERNAL_SYSCALL_ERRNO
#define ERRNO_P INTERNAL_SYSCALL_ERRNO_P

struct timespec;
struct timeval;

extern struct pal_linux_state {
    PAL_NUM         parent_process_id;
    PAL_NUM         process_id;

#ifdef DEBUG
    bool            in_gdb;
#endif

    const char **   environ;

    /* credentails */
    unsigned int    pid;
    unsigned int    uid, gid;

    /* currently enabled signals */
    __sigset_t      set_signals;
    __sigset_t      blocked_signals;

    unsigned long   memory_quota;

#if USE_VDSO_GETTIME == 1
# if USE_CLOCK_GETTIME == 1
    long int (*vdso_clock_gettime) (long int clk, struct timespec * tp);
# else
    long int (*vdso_gettimeofday) (struct timeval *, void *);
# endif
#endif
} linux_state;

#include <asm/fcntl.h>
#include <asm/mman.h>

#ifdef INLINE_SYSCALL
# ifdef __i386__
#  define ARCH_MMAP(addr, len, prot, flags, fd, offset)          \
    ({                                                           \
        struct mmap_arg_struct {                                 \
            unsigned long addr;                                  \
            unsigned long len;                                   \
            unsigned long prot;                                  \
            unsigned long flags;                                 \
            unsigned long fd;                                    \
            unsigned long offset;                                \
        } args = {  .addr   = (unsigned long) (addr),            \
                    .len    = (unsigned long) (len),             \
                    .prot   = (unsigned long) (prot),            \
                    .flags  = (unsigned long) (flags),           \
                    .fd     = (unsigned long) (fd),              \
                    .offset = (unsigned long) (offset), };       \
        INLINE_SYSCALL(mmap, 1, &args);                          \
    })
# else
#  define ARCH_MMAP(addr, len, prot, flags, fd, offset) \
    INLINE_SYSCALL(mmap, 6, (addr), (len), (prot), (flags), (fd), (offset))
# endif
#else
# error "INLINE_SYSCALL not supported"
#endif

#ifndef SIGCHLD
# define SIGCHLD 17
#endif

#ifdef DEBUG
# define ARCH_VFORK()                                                       \
    (linux_state.in_gdb ?                                                   \
     INLINE_SYSCALL(clone, 4, CLONE_VM|CLONE_VFORK|SIGCHLD, 0, NULL, NULL) :\
     INLINE_SYSCALL(clone, 4, CLONE_VM|CLONE_VFORK, 0, NULL, NULL))
#else
# define ARCH_VFORK()                                                       \
    (INLINE_SYSCALL(clone, 4, CLONE_VM|CLONE_VFORK, 0, NULL, NULL))
#endif

#define PRESET_PAGESIZE (1 << 12)

#define DEFAULT_BACKLOG     2048

static inline int HOST_FLAGS (int alloc_type, int prot)
{
    return ((alloc_type & PAL_ALLOC_RESERVE) ? MAP_NORESERVE|MAP_UNINITIALIZED : 0) |
           ((prot & PAL_PROT_WRITECOPY) ? MAP_PRIVATE : MAP_SHARED);
}

static inline int HOST_PROT (int prot)
{
    return prot & (PAL_PROT_READ|PAL_PROT_WRITE|PAL_PROT_EXEC);
}

static inline int HOST_ACCESS (int access)
{
    return (access & (PAL_ACCESS_RDONLY|PAL_ACCESS_WRONLY|PAL_ACCESS_RDWR)) |
           ((access & PAL_ACCESS_APPEND) ? O_APPEND|O_WRONLY : 0);
}

int clone (int (*__fn) (void * __arg), void * __child_stack,
           int __flags, const void * __arg, ...);

/* set/unset CLOEXEC flags of all fds in a handle */
int handle_set_cloexec (PAL_HANDLE handle, bool enable);

/* serialize/deserialize a handle into/from a malloc'ed buffer */
int handle_serialize (PAL_HANDLE handle, void ** data);
int handle_deserialize (PAL_HANDLE * handle, const void * data, int size);

#define ACCESS_R    4
#define ACCESS_W    2
#define ACCESS_X    1

struct stat;
bool stataccess (struct stat * stats, int acc);

/* Locking and unlocking of Mutexes */
int _DkMutexLock (struct mutex_handle * mut);
int _DkMutexLockTimeout (struct mutex_handle * mut, uint64_t timeout);
int _DkMutexUnlock (struct mutex_handle * mut);

void init_child_process (PAL_HANDLE * parent, PAL_HANDLE * exec,
                         PAL_HANDLE * manifest);

void signal_setup (void);

unsigned long _DkSystemTimeQueryEarly (void);

extern char __text_start, __text_end, __data_start, __data_end;
#define TEXT_START (void *) (&__text_start)
#define TEXT_END   (void *) (&__text_end)
#define DATA_START (void *) (&__text_start)
#define DATA_END   (void *) (&__text_end)

#endif /* PAL_LINUX_H */
