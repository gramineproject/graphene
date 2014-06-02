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
 * db_ipc.c
 *
 * This file contains APIs for physical memory bulk copy across processes.
 */

#include "pal_defs.h"
#include "pal_linux_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_error.h"
#include "pal_security.h"
#include "graphene-ipc.h"
#include "api.h"

#include <fcntl.h>
#include <sched.h>

int gipc_open (PAL_HANDLE * handle, const char * type, const char * uri,
               int access, int share, int create, int options)
{
    int64_t token;
    int rv;

    int fd = INLINE_SYSCALL(open, 3, GIPC_FILE, O_RDONLY|O_CLOEXEC, 0);

    if (IS_ERR(fd))
        return -PAL_ERROR_DENIED;

    token = atoi(uri);

    rv = INLINE_SYSCALL(ioctl, 3, fd, GIPC_JOIN, token);

    if (rv < 0) {
        INLINE_SYSCALL(close, 1, fd);
        return -PAL_ERROR_DENIED;
    }

    PAL_HANDLE hdl = malloc(HANDLE_SIZE(gipc));
    SET_HANDLE_TYPE(hdl, gipc);
    hdl->gipc.fd = fd;
    *handle = hdl;
    return 0;
}

int gipc_close (PAL_HANDLE handle)
{
    int ret = INLINE_SYSCALL(close, 1, handle->gipc.fd);

    if (IS_ERR(ret))
        return -PAL_ERROR_BADHANDLE;

    return 0;
}

const char * gipc_getrealpath (PAL_HANDLE handle)
{
    return GIPC_FILE;
}

struct handle_ops gipc_ops = {
        .getrealpath        = &gipc_getrealpath,
        .open               = &gipc_open,
        .close              = &gipc_close,
    };

int _DkCreatePhysicalMemoryChannel (PAL_HANDLE * handle, unsigned long * key)
{
    store_frame(CreatePhysicalMemoryChannel);

    unsigned long token = 0;
    int fd = INLINE_SYSCALL(open, 3, GIPC_FILE, O_RDONLY|O_CLOEXEC, 0);

    if (IS_ERR(fd))
        goto err;


    PAL_HANDLE hdl = malloc(HANDLE_SIZE(gipc));
    SET_HANDLE_TYPE(hdl, gipc);
    hdl->gipc.fd = fd;

    // ioctl to create a new queue
    token = INLINE_SYSCALL(ioctl, 3, fd, GIPC_CREATE, 0);
    if (token < 0)
        goto err_fd;

    *handle = hdl;
    *key = token;
    return 0;

 err_fd:
    INLINE_SYSCALL(close, 1, fd);

 err:
    return -PAL_ERROR_DENIED;
}

int _DkPhysicalMemoryCommit (PAL_HANDLE channel, int entries, void ** addrs,
                             unsigned long * sizes, int flags)
{
    int fd = channel->gipc.fd;

    struct gipc_send gs;
    int nsent = 0, n;
    unsigned long npagesent = 0;

    while (nsent < entries) {
        n = entries - nsent;

        if (n > ADDR_ENTS)
            n = ADDR_ENTS;

        gs.entries  = n;
        gs.addr = (unsigned long *) (addrs + nsent);
        gs.len  = (unsigned long *) (sizes + nsent);

        int ret = INLINE_SYSCALL(ioctl, 3, fd, GIPC_SEND, &gs);

        if (IS_ERR(ret)) {
            if (!npagesent)
                return -PAL_ERROR_DENIED;
            return npagesent;
        }

        npagesent += ret;
        nsent += n;
    }

    return npagesent;
}

int _DkPhysicalMemoryMap (PAL_HANDLE channel, int entries, void ** addrs,
                          unsigned long * sizes, unsigned int * prots)
{
    int fd = channel->gipc.fd;
    struct gipc_recv gr;
    int nrecv = 0, n;
    unsigned long npagerecv = 0;

    while (nrecv < entries) {
        n = entries - nrecv;

        if (n > ADDR_ENTS)
            n = ADDR_ENTS;

        gr.entries = n;
        gr.addr = (unsigned long *) (addrs + nrecv);
        gr.len  = (unsigned long *) (sizes + nrecv);
        gr.prot = (int *) (prots + nrecv);

        int ret = INLINE_SYSCALL(ioctl, 3, fd, GIPC_RECV, &gr);

        if (IS_ERR(ret)) {
            if (!npagerecv)
                return -PAL_ERROR_DENIED;
            return npagerecv;
        }

        npagerecv += ret;
        nrecv += n;
    }

    return npagerecv;
}
