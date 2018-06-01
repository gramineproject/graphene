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

/* Simpler mutex design: a single variable that tracks whether the 
 * mutex is locked (just waste a 64 bit word for now).  State is 1 (locked) or
 * 0 (unlocked).
 * Keep a count of how many threads are waiting on the mutex.
 * If DEBUG_MUTEX is defined,
 * mutex_handle will record the owner of mutex locking. */
typedef struct mutex_handle {
    volatile int64_t locked;
    struct atomic_int nwaiters;
#ifdef DEBUG_MUTEX
    int owner;
#endif
} PAL_LOCK;

/* Initializer of Mutexes */
#define MUTEX_HANDLE_INIT    { .locked = 0, .nwaiters.counter = 0 }
#define INIT_MUTEX_HANDLE(m)  do { m->locked = 0; atomic_set(&m->nwaiters, 0); } while (0)

#define LOCK_INIT MUTEX_HANDLE_INIT
#define INIT_LOCK(lock) INIT_MUTEX_HANDLE(lock);

#define _DkInternalLock _DkMutexLock
#define _DkInternalUnlock _DkMutexUnlock

/* Locking and unlocking of Mutexes */
int _DkMutexLock (struct mutex_handle * mut);
int _DkMutexLockTimeout (struct mutex_handle * mut, uint64_t timeout);
int _DkMutexUnlock (struct mutex_handle * mut);

typedef struct {
    PAL_HDR hdr;
#if TRACE_HEAP_LEAK == 1
    struct heap_trace_info {
        /* maintaining a list of handles */
        struct pal_handle ** pprev, * next;
        /* trace the PC where the handle is created */
        PAL_PTR caller;
    } heap_trace;
#endif
} PAL_RESERVED_HDR;

typedef struct pal_handle
{
    /* TSAI: Here we define the internal types of PAL_HANDLE
     * in PAL design, user has not to access the content inside the
     * handle, also there is no need to allocate the internal
     * handles, so we hide the type name of these handles on purpose.
     */
    PAL_HDR hdr;
    
    union {
        struct {
            PAL_IDX fds[2];
        } generic;

        struct {
            PAL_IDX fd;
            PAL_NUM offset;
            PAL_BOL append;
            PAL_BOL pass;
            PAL_STR realpath;
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
            PAL_NUM token;
        } gipc;

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
            PAL_PTR addr;
        } mcast;

        struct {
            PAL_IDX tid;
        } thread;

        struct {
            struct mutex_handle mut;
        } mutex;

        struct {
            struct atomic_int signaled;
            struct atomic_int nwaiters;
            PAL_BOL isnotification;
        } event;
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
    uint64_t rsp, rbp, rbx, rsi, rdi, r12, r13, r14, r15;
#else
# error "unsupported architecture"
#endif
};

#ifdef __x86_64__
# define store_register(reg, var)     \
    asm volatile ("movq %%" #reg ", %0" : "=a" (var) :: "memory");

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

/* When a PAL call is issued, a special PAL_FRAME is placed on the stack.
 * This stores both a magic identifier, debugging information, 
 * as well as callee-saved state.  This is used as a way to deal
 * with PAL-internal failures where the goal is to exit the PAL and return a
 * failure.
 * 
 * Arguably, an alternative is to unwind the stack and handle error cases at
 * each stage.  In general, this is probably more robust, but would take work
 * in the short term.  The one exception where the current strategy is
 * probably better is when the PAL gets in a state where the code is
 * unrecoverable, but ideally, this shouldn't happen.
 */

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

#if TRACE_HEAP_LEAK == 1

/* The following code adds a piece of information
   in each handle to trace heap leakage. */

extern PAL_HANDLE heap_alloc_head;
extern PAL_LOCK   heap_alloc_trace_lock;

/* call the following function in GDB */
typedef struct {
    PAL_PTR caller;
    PAL_NUM count;
} HEAP_ALLOC_RECORD;

extern HEAP_ALLOC_RECORD * collect_heap_alloc_records (PAL_NUM max_records);

static inline
void __trace_heap (PAL_HANDLE handle, struct pal_frame * frame)
{
    _DkInternalLock(&heap_alloc_trace_lock);

    handle->hdr.heap_trace.caller = ((PAL_PTR *)frame->arch.rbp)[1];

    /* Add the handle to the list */
    if (heap_alloc_head)
        heap_alloc_head->hdr.heap_trace.pprev
                                    = &handle->hdr.heap_trace.next;
    handle->hdr.heap_trace.next     = heap_alloc_head;
    handle->hdr.heap_trace.pprev    = &heap_alloc_head;
    heap_alloc_head                 = handle;

    _DkInternalUnlock(&heap_alloc_trace_lock);
}

#define TRACE_HEAP(handle) \
    do { if (handle) __trace_heap(handle, &frame); } while (0)

static inline
void __untrace_heap (PAL_HANDLE handle)
{
    _DkInternalLock(&heap_alloc_trace_lock);

    /* remove the handle from the list */
    *handle->hdr.heap_trace.pprev = handle->hdr.heap_trace.next;
    if (handle->hdr.heap_trace.next)
        handle->hdr.heap_trace.next->hdr.heap_trace.pprev
            = handle->hdr.heap_trace.pprev;

    handle->hdr.heap_trace.pprev = NULL;
    handle->hdr.heap_trace.next  = NULL;

    _DkInternalUnlock(&heap_alloc_trace_lock);
}

#define UNTRACE_HEAP(handle) \
    do { if (handle) __untrace_heap(handle); } while (0)

#endif /* TRACE_HEAP_LEAK == 1 */

#endif /* PAL_HOST_H */
