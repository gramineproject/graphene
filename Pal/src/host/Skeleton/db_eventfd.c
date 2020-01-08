/* Copyright (C) 2019 Intel Corporation
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
 * db_eventfd.c
 *
 * This file contains operations to handle streams with URIs that have "eventfd:".
 */

#include "api.h"
#include "pal.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"

/* `type` must be eventfd, `uri` & `access` & `share` are unused, `create` holds eventfd's initval, 
 * `options` holds eventfd's flags */
static int eventfd_pal_open(PAL_HANDLE* handle, const char* type, const char* uri, int access,
                            int share, int create, int options) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* offset does not apply here. */
static int64_t eventfd_pal_read(PAL_HANDLE handle, uint64_t offset, uint64_t len, void* buffer) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* offset does not apply here. */
static int64_t eventfd_pal_write(PAL_HANDLE handle, uint64_t offset, uint64_t len,
                                 const void* buffer) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* gets used for polling(query) on eventfd from LibOS. */
static int eventfd_pal_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int eventfd_pal_close(PAL_HANDLE handle) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

struct handle_ops eventfd_ops = {
    .open           = &eventfd_pal_open,
    .read           = &eventfd_pal_read,
    .write          = &eventfd_pal_write,
    .close          = &eventfd_pal_close,
    .attrquerybyhdl = &eventfd_pal_attrquerybyhdl,
};
