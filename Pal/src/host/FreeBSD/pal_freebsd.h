/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

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

#ifndef PAL_FREEBSD_H
#define PAL_FREEBSD_H

#include "pal_defs.h"
#include "pal_freebsd_defs.h"
#include "pal.h"
#include "pal_freebsd_error.h"

typedef int __kernel_pid_t;

#include <sigset.h>
#include <sys/syscall.h>
#include <unistd.h>

#undef __htonl
#undef __ntohl
#undef __htons
#undef __ntohs

#ifdef __x86_64__
# include "sysdep-x86_64.h"
#endif

#define PAL_LOADER XSTRINGIFY(PAL_LOADER_PATH)

#define IS_ERR INTERNAL_SYSCALL_ERROR
#define IS_ERR_P INTERNAL_SYSCALL_ERROR_P
#define ERRNO INTERNAL_SYSCALL_ERRNO
#define ERRNO_P INTERNAL_SYSCALL_ERRNO_P

int getrand (void * buffer, size_t size);

struct timespec;
struct timeval;
extern struct pal_bsd_state {
    /* state */
    unsigned long   start_time;

    /* credentails */
    unsigned int    pid;
    unsigned int    uid, gid;
    unsigned int    parent_pid;
    /* currently enabled signals */
    _sigset_t       sigset;
  
    unsigned long   memory_quota;
} bsd_state;

#include <sys/mman.h>
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

#define PRESET_PAGESIZE (1 << 12)

#define DEFAULT_BACKLOG     2048

static inline int HOST_FLAGS (int alloc_type, int prot)
{
    return 
           ((prot & PAL_PROT_WRITECOPY) ? MAP_PRIVATE : MAP_SHARED);
}

static inline int HOST_PROT (int prot)
{
    return prot & (PAL_PROT_READ|PAL_PROT_WRITE|PAL_PROT_EXEC);
}

int __clone (int (*__fn) (void * __arg), void * __child_stack,
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

#include <sys/fcntl.h>

static inline int HOST_FILE_OPEN (int access_type, int create_type,
        int options)
{
    return ((access_type)|
            (create_type & PAL_CREAT_TRY ? O_CREAT : 0) |
            (create_type & PAL_CREAT_ALWAYS ? O_EXCL : 0) |
            (options));
}

#include<sys/stat.h>

static inline int HOST_PERM (int share_type)
{
    return((share_type & PAL_SHARE_GLOBAL_X ? S_IXUSR | S_IXGRP | S_IXOTH :
            0)|
           (share_type & PAL_SHARE_GLOBAL_W ? S_IWUSR | S_IWGRP | S_IWOTH :
            0)|
           (share_type & PAL_SHARE_GLOBAL_R ? S_IRUSR | S_IRGRP | S_IROTH :
            0)|
           (share_type & PAL_SHARE_GROUP_X ? S_IXGRP : 0) | 
           (share_type & PAL_SHARE_GROUP_W ? S_IWGRP : 0) | 
           (share_type & PAL_SHARE_GROUP_R ? S_IRGRP : 0) | 
           (share_type & PAL_SHARE_OWNER_X ? S_IXUSR : 0) | 
           (share_type & PAL_SHARE_OWNER_W ? S_IWUSR : 0) | 
           (share_type & PAL_SHARE_OWNER_R ? S_IRUSR : 0));
}

static inline int HOST_OPTIONS (int options)
{
    return((options & PAL_OPTION_NONBLOCK ? O_NONBLOCK : 0 )
            );
}

#include <sys/socket.h>

static inline int HOST_SOCKET_OPTIONS (int options)
{
    return((options & PAL_OPTION_NONBLOCK ? SOCK_NONBLOCK : 0 )
            );
}

/* Locking and unlocking of Mutexes */
int _DkMutexLock (struct mutex_handle * mut);
int _DkMutexLockTimeout (struct mutex_handle * mut, int timeout);
int _DkMutexUnlock (struct mutex_handle * mut);

/*UMTX constants*/
#define UMTX_OP_WAIT		2
#define UMTX_OP_WAKE		3
#define UMTX_OP_WAIT_UINT	11

void init_child_process (PAL_HANDLE * parent, PAL_HANDLE * exec,
                         PAL_HANDLE * manifest);
void signal_setup (void);

extern char __text_start, __text_end, __data_start, __data_end;
#define TEXT_START (void *) (&__text_start)
#define TEXT_END   (void *) (&__text_end)
#define DATA_START (void *) (&__text_start)
#define DATA_END   (void *) (&__text_end)

#endif /* PAL_FREEBSD_H */
