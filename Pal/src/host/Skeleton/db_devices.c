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
 * db_device.c
 *
 * This file contains operands to handle streams with URIs that start with "dev:".
 */

#include "api.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"

#define DEVICE_OPS(handle)                                                             \
    ({                                                                                 \
        int _type = (handle)->dev.dev_type;                                            \
        (_type <= 0 || _type >= PAL_DEVICE_TYPE_BOUND) ? NULL : pal_device_ops[_type]; \
    })

enum {
    device_type_none = 0,
    device_type_term,
    PAL_DEVICE_TYPE_BOUND,
};

static struct handle_ops term_ops;

static const struct handle_ops* pal_device_ops[PAL_DEVICE_TYPE_BOUND] = {
    NULL,
    &term_ops,
};

/* parse_device_uri scans the uri, parses the prefix of the uri and searches for stream handler
 * which will open or access the device. */
static int parse_device_uri(const char** uri, char** type, struct handle_ops** ops) {
    struct handle_ops* dops = NULL;
    const char* p;
    const char* u = *uri;

    for (p = u; *p && *p != ',' && *p != '/'; p++)
        ;

    if (strstartswith_static(u, "tty"))
        dops = &term_ops;

    if (!dops)
        return -PAL_ERROR_NOTSUPPORT;

    *uri = *p ? p + 1 : p;
    if (type) {
        *type = malloc_copy(u, p - u + 1);
        if (!*type)
            return -PAL_ERROR_NOMEM;
        (*type)[p - u] = '\0';
    }
    if (ops)
        *ops = dops;
    return 0;
}

static int64_t char_read(PAL_HANDLE handle, uint64_t offset, uint64_t count, void* buffer);
static int64_t char_write(PAL_HANDLE handle, uint64_t offset, uint64_t count, const void* buffer);
static int term_attrquery(const char* type, const char* uri, PAL_STREAM_ATTR* attr);
static int term_attrquerybyhdl(PAL_HANDLE hdl, PAL_STREAM_ATTR* attr);

/* 'open' operation for terminal stream */
static int term_open(PAL_HANDLE* handle, const char* type, const char* uri, int access, int share,
                     int create, int options) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int term_close(PAL_HANDLE handle) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* 'attrquery' operation for terminal stream */
static int term_attrquery(const char* type, const char* uri, PAL_STREAM_ATTR* attr) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* 'attrquery' operation for terminal stream */
static int term_attrquerybyhdl(PAL_HANDLE hdl, PAL_STREAM_ATTR* attr) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static struct handle_ops term_ops = {
    .open           = &term_open,
    .close          = &term_close,
    .read           = &char_read,
    .write          = &char_write,
    .attrquery      = &term_attrquery,
    .attrquerybyhdl = &term_attrquerybyhdl,
};

/* 'read' operation for character streams. */
static int64_t char_read(PAL_HANDLE handle, uint64_t offset, uint64_t size, void* buffer) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* 'write' operation for character streams. */
static int64_t char_write(PAL_HANDLE handle, uint64_t offset, uint64_t size, const void* buffer) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* 'open' operation for device streams */
static int dev_open(PAL_HANDLE* handle, const char* type, const char* uri, int access, int share,
                    int create, int options) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* 'read' operation for device stream */
static int64_t dev_read(PAL_HANDLE handle, uint64_t offset, uint64_t size, void* buffer) {
    const struct handle_ops* ops = DEVICE_OPS(handle);

    if (!ops || !ops->read)
        return -PAL_ERROR_NOTSUPPORT;

    return ops->read(handle, offset, size, buffer);
}

/* 'write' operation for device stream */
static int64_t dev_write(PAL_HANDLE handle, uint64_t offset, uint64_t size, const void* buffer) {
    const struct handle_ops* ops = DEVICE_OPS(handle);

    if (!ops || !ops->write)
        return -PAL_ERROR_NOTSUPPORT;

    return ops->write(handle, offset, size, buffer);
}

/* 'close' operation for device streams */
static int dev_close(PAL_HANDLE handle) {
    const struct handle_ops* ops = DEVICE_OPS(handle);

    if (ops && ops->close)
        return ops->close(handle);

    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* 'delete' operation for device streams */
static int dev_delete(PAL_HANDLE handle, int access) {
    const struct handle_ops* ops = DEVICE_OPS(handle);

    if (!ops || !ops->delete)
        return -PAL_ERROR_DENIED;

    int ret = dev_close(handle);

    if (ret < 0)
        return ret;

    return ops->delete(handle, access);
}

/* 'flush' operation for device streams */
static int dev_flush(PAL_HANDLE handle) {
    const struct handle_ops* ops = DEVICE_OPS(handle);

    if (ops && ops->flush)
        return ops->flush(handle);

    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* 'attrquery' operation for device streams */
static int dev_attrquery(const char* type, const char* uri, PAL_STREAM_ATTR* attr) {
    struct handle_ops* ops = NULL;
    char* dev_type = NULL;
    int ret = 0;

    ret = parse_device_uri(&uri, &dev_type, &ops);

    if (ret < 0)
        return ret;

    if (!ops || !ops->attrquery)
        return -PAL_ERROR_NOTSUPPORT;

    ret = ops->attrquery(dev_type, uri, attr);
    free(dev_type);
    return ret;
}

/* 'attrquerybyhdl' operation for device stream */
static int dev_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    const struct handle_ops* ops = DEVICE_OPS(handle);

    if (ops && ops->attrquerybyhdl)
        return ops->attrquerybyhdl(handle, attr);

    return -PAL_ERROR_NOTIMPLEMENTED;
}

static const char* dev_getrealpath(PAL_HANDLE handle) {
    return NULL;
}

struct handle_ops dev_ops = {
    .getrealpath    = &dev_getrealpath,
    .open           = &dev_open,
    .read           = &dev_read,
    .write          = &dev_write,
    .close          = &dev_close,
    .delete         = &dev_delete,
    .flush          = &dev_flush,
    .attrquery      = &dev_attrquery,
    .attrquerybyhdl = &dev_attrquerybyhdl,
};
