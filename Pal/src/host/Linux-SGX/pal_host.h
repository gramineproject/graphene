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

/* Spinlocking */
typedef struct spinlock {
    struct atomic_int value;
} PAL_LOCK;

int _DkSpinLock (struct spinlock * lock);
int _DkSpinUnlock (struct spinlock * lock);

#define LOCK_INIT   { .value =  { 0 } }
#define _DkInternalLock _DkSpinLock
#define _DkInternalUnlock _DkSpinUnlock

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

typedef struct pal_handle
{
    /*
     * Here we define the internal structure of PAL_HANDLE.
     * user has no access to the content inside these handles.
     */

    PAL_HDR hdr;
    union {
        struct {
            PAL_IDX fds[2];
        } generic;

        struct {
            PAL_IDX fd;
            PAL_BOL append;
            PAL_BOL pass;
            PAL_STR realpath;
            PAL_NUM total;
            PAL_PTR stubs;
        } file;

        struct {
            PAL_IDX fd;
            PAL_NUM pipeid;
            PAL_BOL nonblocking;
        } pipe;

        struct {
            PAL_IDX fds[2];
            PAL_BOL nonblocking;
        } pipeprv;

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
        } gipc;

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
            PAL_IDX stream_in, stream_out;
            PAL_IDX cargo;
            PAL_IDX pid;
            PAL_BOL nonblocking;
        } process;

        struct {
            PAL_IDX cli;
            PAL_IDX srv;
            PAL_IDX port;
            PAL_BOL nonblocking;
        } mcast;

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

#define RFD(n)          (00001 << (n))
#define WFD(n)          (00010 << (n))
#define WRITEABLE(n)    (00100 << (n))
#define ERROR(n)        (01000 << (n))
#define MAX_FDS         (3)
#define HAS_FDS         (00077)

#define HANDLE_TYPE(handle)  ((handle)->hdr.type)

struct arch_frame {
#ifdef __x86_64__
    unsigned long rsp, rbp, rbx, rsi, rdi, r12, r13, r14, r15;
#else
# error "unsupported architecture"
#endif
};

#ifdef __x86_64__
# define store_register(reg, var)     \
    asm volatile ("movq %%" #reg ", %0" : "=g" (var) :: "memory");

# define store_register_in_frame(reg, f)     store_register(reg, (f)->reg)

# define arch_store_frame(f)                     \
    store_register_in_frame(rsp, f)              \
    store_register_in_frame(rbp, f)              \
    store_register_in_frame(rbx, f)              \
    store_register_in_frame(rsi, f)              \
    store_register_in_frame(rdi, f)              \
    store_register_in_frame(r12, f)              \
    store_register_in_frame(r13, f)              \
    store_register_in_frame(r14, f)              \
    store_register_in_frame(r15, f)

# define restore_register(reg, var, clobber...)  \
    asm volatile ("movq %0, %%" #reg :: "g" (var) : "memory", ##clobber);

# define restore_register_in_frame(reg, f)       \
    restore_register(reg, (f)->reg,              \
                     "r15", "r14", "r13", "r12", "rdi", "rsi", "rbx")

# define arch_restore_frame(f)                   \
    restore_register_in_frame(r15, f)            \
    restore_register_in_frame(r14, f)            \
    restore_register_in_frame(r13, f)            \
    restore_register_in_frame(r12, f)            \
    restore_register_in_frame(rdi, f)            \
    restore_register_in_frame(rsi, f)            \
    restore_register_in_frame(rbx, f)            \
    restore_register_in_frame(rbp, f)            \
    restore_register_in_frame(rsp, f)
#else /* __x86_64__ */
# error "unsupported architecture"
#endif

#define PAL_FRAME_IDENTIFIER    (0xdeaddeadbeefbeef)

struct pal_frame {
    volatile uint64_t           identifier;
    void *                      func;
    const char *                funcname;
    struct arch_frame           arch;
};

/* DEP 12/25/17: This frame storage thing is important to mark volatile.
 * The compiler should not optimize out any of these changes, and 
 * because some accesses can happen during an exception, these are not
 * visible to the compiler in an otherwise stack-local variable (so the
 * compiler will try to optimize out these assignments.
 */
static inline
void __store_frame (volatile struct pal_frame * frame,
                    void * func, const char * funcname)
{
    arch_store_frame(&frame->arch)
    frame->func = func;
    frame->funcname = funcname;
    asm volatile ("nop" ::: "memory");
    frame->identifier = PAL_FRAME_IDENTIFIER;
}

#define ENTER_PAL_CALL(name)                \
    struct pal_frame frame;                 \
    __store_frame(&frame, &(name), #name)


static inline
void __clear_frame (volatile struct pal_frame * frame)
{
    if (frame->identifier == PAL_FRAME_IDENTIFIER) {
        asm volatile ("nop" ::: "memory");
        frame->identifier = 0;
    }
}

#define LEAVE_PAL_CALL()                    \
    do {                                    \
        __clear_frame(&frame);              \
    } while (0)

#define LEAVE_PAL_CALL_RETURN(retval)       \
    do {                                    \
        __clear_frame(&frame);              \
        return (retval);                    \
    } while (0)

#endif /* PAL_HOST_H */
