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

/* internal Mutex design, the structure has to align at integer boundary
   because it is required by futex call. If DEBUG_MUTEX is defined,
   mutex_handle will record the owner of mutex locking. */
typedef struct mutex_handle {
    struct atomic_int value;
#ifdef DEBUG_MUTEX
    int owner;
#endif
} PAL_LOCK;

/* Initializer of Mutexes */
#define MUTEX_HANDLE_INIT    { .value = { .counter = 1 } }
#define INIT_MUTEX_HANDLE(mut)  \
    do { atomic_set(&(mut)->value, 1); } while (0)

#define LOCK_INIT MUTEX_HANDLE_INIT
#define INIT_LOCK(lock) INIT_MUTEX_HANDLE(lock);

#define _DkInternalLock _DkMutexLock
#define _DkInternalUnlock _DkMutexUnlock
typedef union pal_handle
{
    /* TSAI: Here we define the internal types of PAL_HANDLE
     * in PAL design, user has not to access the content inside the
     * handle, also there is no need to allocate the internal
     * handles, so we hide the type name of these handles on purpose.
     */

    struct {
        PAL_IDX type;
        PAL_FLG flags;
        PAL_REF ref;
        PAL_IDX fds[];
    } __in;

    struct {
        PAL_HDR __in;
        PAL_IDX fd;
        PAL_NUM offset;
        PAL_BOL append;
        PAL_BOL pass;
        PAL_STR realpath;
    } file;

    struct {
        PAL_HDR __in;
        PAL_IDX fd;
        PAL_NUM pipeid;
        PAL_BOL nonblocking;
    } pipe;

    struct {
        PAL_HDR __in;
        PAL_IDX fds[2];
        PAL_BOL nonblocking;
    } pipeprv;

    struct {
        PAL_HDR __in;
        PAL_IDX fd_in, fd_out;
        PAL_IDX dev_type;
        PAL_BOL destroy;
        PAL_STR realpath;
    } dev;

    struct {
        PAL_HDR __in;
        PAL_IDX fd;
        PAL_STR realpath;
        PAL_PTR buf;
        PAL_PTR ptr;
        PAL_PTR end;
        PAL_BOL endofstream;
    } dir;

    struct {
        PAL_HDR __in;
        PAL_IDX fd;
        PAL_NUM token;
    } gipc;

    struct {
        PAL_HDR __in;
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
        PAL_HDR __in;
        PAL_IDX stream_in, stream_out;
        PAL_IDX cargo;
        PAL_IDX pid;
        PAL_BOL nonblocking;
    } process;

    struct {
        PAL_HDR __in;
        PAL_IDX cli;
        PAL_IDX srv;
        PAL_IDX port;
        PAL_BOL nonblocking;
    } mcast;

    struct {
        PAL_HDR __in;
        PAL_IDX tid;
    } thread;

    struct {
        PAL_HDR __in;
        struct atomic_int nwaiters;
        PAL_NUM max_value;
        union {
            struct mutex_handle mut;
            struct atomic_int i;
        } value;
    } semaphore;

    struct {
        PAL_HDR __in;
        struct atomic_int signaled;
        struct atomic_int nwaiters;
        PAL_BOL isnotification;
    } event;
} * PAL_HANDLE;

#define RFD(n)          (00001 << (n))
#define WFD(n)          (00010 << (n))
#define WRITEABLE(n)    (00100 << (n))
#define ERROR(n)        (01000 << (n))
#define MAX_FDS         (3)
#define HAS_FDS         (00077)

#define HANDLE_TYPE(handle)  ((handle)->__in.type)
#endif /* PAL_HOST_H */
