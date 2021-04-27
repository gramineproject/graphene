/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains definition of PAL host ABI.
 */

#ifndef PAL_HOST_H
#define PAL_HOST_H

#ifndef IN_PAL
#error "cannot be included outside PAL"
#endif

#include <stdbool.h>
#include <stdint.h>

#include "atomic.h"

/* Simpler mutex design: a single variable that tracks whether the
 * mutex is locked.  State is 1 (locked) or 0 (unlocked).
 * Keep a count of how many threads are waiting on the mutex.
 *
 * If DEBUG_MUTEX is defined, mutex_handle will record the owner of mutex locking.
 */
typedef struct mutex_handle {
    uint32_t locked;
    struct atomic_int nwaiters;
#ifdef DEBUG_MUTEX
    int owner;
#endif
} PAL_LOCK;

/* Initializer of Mutexes */
#define MUTEX_HANDLE_INIT \
    { .locked = 0, .nwaiters.counter = 0 }
#define INIT_MUTEX_HANDLE(m)           \
    do {                               \
        (m)->locked = 0;               \
        atomic_set(&(m)->nwaiters, 0); \
    } while (0)

#define LOCK_INIT       MUTEX_HANDLE_INIT
#define INIT_LOCK(lock) INIT_MUTEX_HANDLE(lock)

/* Locking and unlocking of Mutexes */
int _DkMutexLock(struct mutex_handle* mut);
int _DkMutexLockTimeout(struct mutex_handle* mut, int64_t timeout_us);
void _DkMutexUnlock(struct mutex_handle* mut);

typedef struct {
    PAL_HDR hdr;
} PAL_RESERVED_HDR;

typedef struct {
    char str[PIPE_NAME_MAX];
} PAL_PIPE_NAME;

typedef struct pal_handle {
    /* TSAI: Here we define the internal types of PAL_HANDLE
     * in PAL design, user has not to access the content inside the
     * handle, also there is no need to allocate the internal
     * handles, so we hide the type name of these handles on purpose.
     */
    PAL_HDR hdr;

    union {
        struct {
            PAL_IDX fds[MAX_FDS];
        } generic;

        struct {
            PAL_IDX fd;
            PAL_STR realpath;
            /*
             * map_start is to request this file should be mapped to this
             * address. When fork is emulated, the address is already
             * determined by parent process.
             */
            PAL_PTR map_start;
            PAL_BOL seekable; /* regular files are seekable, FIFO pipes are not */
        } file;

        struct {
            PAL_IDX fd;
            PAL_PIPE_NAME name;
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
            PAL_IDX fd;
            PAL_BOL nonblocking;
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
            PAL_BOL reuseaddr;
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
        } process;

        struct {
            PAL_IDX tid;
            PAL_PTR stack;
        } thread;

        struct {
            struct mutex_handle mut;
        } mutex;

        struct {
            uint32_t signaled;
            bool auto_clear;
        } event;
    };
}* PAL_HANDLE;

#define RFD(n)   (1 << (MAX_FDS * 0 + (n)))
#define WFD(n)   (1 << (MAX_FDS * 1 + (n)))
#define ERROR(n) (1 << (MAX_FDS * 2 + (n)))

#define HANDLE_TYPE(handle) ((handle)->hdr.type)

int arch_do_rt_sigprocmask(int sig, int how);
int arch_do_rt_sigaction(int sig, void* handler,
                         const int* async_signals, size_t num_async_signals);

#endif /* PAL_HOST_H */
