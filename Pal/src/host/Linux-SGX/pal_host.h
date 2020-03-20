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
 * pal_host.h
 *
 * This file contains definition of PAL host ABI.
 */

#ifndef PAL_HOST_H
#define PAL_HOST_H

#ifndef IN_PAL
# error "cannot be included outside PAL"
#endif

#include <atomic.h>
#include <spinlock.h>

typedef spinlock_t PAL_LOCK;

#define LOCK_INIT INIT_SPINLOCK_UNLOCKED
#define _DkInternalLock spinlock_lock
#define _DkInternalUnlock spinlock_unlock
#define _DkInternalIsLocked spinlock_is_locked

void * malloc_untrusted (int size);
void free_untrusted (void * mem);

#include <list.h>

/* Simpler mutex design: a single variable that tracks whether the mutex
 * is locked (just waste a 64 bit word for now).  State is 1 (locked) or
 * 0 (unlocked).
 *
 * Keep a count of how many threads are waiting on the mutex.
 *
 * If DEBUG_MUTEX is defined, mutex_handle will record the owner of
 * mutex locking. */
struct mutex_handle {
    volatile int64_t * locked;
    struct atomic_int nwaiters;
#ifdef DEBUG_MUTEX
    int owner;
#endif
};

/* Initializer of Mutexes */
#define MUTEX_HANDLE_INIT    { .u = 0 }
#define INIT_MUTEX_HANDLE(m)  do { (m)->u = 0; } while (0)

DEFINE_LIST(pal_handle_thread);
struct pal_handle_thread {
    PAL_HDR reserved;
    PAL_IDX tid;
    PAL_PTR tcs;
    LIST_TYPE(pal_handle_thread) list;
    void * param;
};

/* RPC streams are encrypted with 256-bit AES keys */
typedef uint8_t PAL_SESSION_KEY[32];

typedef struct pal_handle
{
    /*
     * Here we define the internal structure of PAL_HANDLE.
     * user has no access to the content inside these handles.
     */

    PAL_HDR hdr;
    union {
        struct {
            PAL_IDX fds[MAX_FDS];
        } generic;

        struct {
            PAL_IDX fd;
            PAL_STR realpath;
            PAL_NUM total;
            /* below fields are used only for trusted files */
            PAL_PTR stubs;    /* contains hashes of file chunks */
            PAL_PTR umem;     /* valid only when stubs != NULL */
        } file;

        struct {
            PAL_IDX fd;
            PAL_NUM pipeid;
            PAL_BOL nonblocking;
        } pipe;

        struct {
            PAL_IDX fds[MAX_FDS];
            PAL_BOL nonblocking;
        } pipeprv;

        struct {
            PAL_IDX fd;
            /* TODO: add other flags in future, if needed (e.g., semaphore) */
            PAL_BOL nonblocking;
        } eventfd;

        struct {
            PAL_IDX fd_in, fd_out;
            PAL_IDX dev_type;
            PAL_BOL destroy;
            PAL_STR realpath;
        } dev;

        struct {
            PAL_IDX fd;
            PAL_STR realpath;
            PAL_PTR buf;
            PAL_PTR ptr;
            PAL_PTR end;
            PAL_BOL endofstream;
        } dir;

        struct {
            PAL_IDX fd;
            PAL_PTR bind;
            PAL_PTR conn;
            PAL_BOL nonblocking;
            PAL_NUM linger;
            PAL_NUM receivebuf;
            PAL_NUM sendbuf;
            PAL_NUM receivetimeout;
            PAL_NUM sendtimeout;
            PAL_BOL tcp_cork;
            PAL_BOL tcp_keepalive;
            PAL_BOL tcp_nodelay;
        } sock;

        struct {
            PAL_IDX stream;
            PAL_IDX pid;
            PAL_BOL nonblocking;
            PAL_SESSION_KEY session_key;
            void* ssl_ctx;
        } process;

        struct pal_handle_thread thread;

        struct {
            struct atomic_int nwaiters;
            PAL_NUM max_value;
            union {
                struct mutex_handle mut;
            } mutex;

            struct {
                struct atomic_int * signaled;
                struct atomic_int nwaiters;
                PAL_BOL isnotification;
            } event;
        };
    };
} * PAL_HANDLE;

#define RFD(n)          (1 << (MAX_FDS*0 + (n)))
#define WFD(n)          (1 << (MAX_FDS*1 + (n)))
#define ERROR(n)        (1 << (MAX_FDS*2 + (n)))

#define HANDLE_TYPE(handle)  ((handle)->hdr.type)

#endif /* PAL_HOST_H */
