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
 * db_pipes.c
 *
 * This file contains oeprands to handle streams with URIs that start with "pipe:" or "pipe.srv:".
 */

#include "api.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"

static int pipe_listen(PAL_HANDLE* handle, PAL_NUM pipeid, int create) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int pipe_waitforclient(PAL_HANDLE handle, PAL_HANDLE* client) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int pipe_connect(PAL_HANDLE* handle, PAL_NUM pipeid, PAL_IDX connid, int create) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int pipe_private(PAL_HANDLE* handle) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* 'open' operation of pipe stream. For each pipe stream, it is identified by a decimal number in
   URI. There could be two types: pipe and pipe.srv. They behave pretty much the same, except they
   are two ends of the pipe. */
static int pipe_open(PAL_HANDLE* handle, const char* type, const char* uri, int access, int share,
                     int create, int options) {
    if (!strcmp_static(type, URI_TYPE_PIPE) && !*uri)
        return pipe_private(handle);

    char* endptr;
    PAL_NUM pipeid = strtol(uri, &endptr, 10);
    PAL_IDX connid = 0;

    if (*endptr == ':') {
        if (create & PAL_CREATE_TRY)
            return -PAL_ERROR_INVAL;

        connid = strtol(endptr + 1, &endptr, 10);
    }

    if (*endptr)
        return -PAL_ERROR_INVAL;

    if (!strcmp_static(type, URI_TYPE_PIPE_SRV))
        return pipe_listen(handle, pipeid, create);

    if (!strcmp_static(type, URI_TYPE_PIPE))
        return pipe_connect(handle, pipeid, connid, create);

    return -PAL_ERROR_INVAL;
}

/* 'read' operation of pipe stream. offset does not apply here. */
static int64_t pipe_read(PAL_HANDLE handle, uint64_t offset, uint64_t len, void* buffer) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* 'write' operation of pipe stream. offset does not apply here. */
static int64_t pipe_write(PAL_HANDLE handle, uint64_t offset, uint64_t len, const void* buffer) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* 'close' operation of pipe stream. */
static int pipe_close(PAL_HANDLE handle) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* 'delete' operation of pipe stream. */
static int pipe_delete(PAL_HANDLE handle, int access) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int pipe_getname(PAL_HANDLE handle, char* buffer, size_t count) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

struct handle_ops pipe_ops = {
    .getname       = &pipe_getname,
    .open          = &pipe_open,
    .waitforclient = &pipe_waitforclient,
    .read          = &pipe_read,
    .write         = &pipe_write,
    .close         = &pipe_close,
    .delete        = &pipe_delete,
};

struct handle_ops pipeprv_ops = {
    .open  = &pipe_open,
    .read  = &pipe_read,
    .write = &pipe_write,
    .close = &pipe_close,
};
