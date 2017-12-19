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
 * db_device.c
 *
 * This file contains operands to handle streams with URIs that start with
 * "dev:".
 */

#include "pal_defs.h"
#include "pal_linux_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_debug.h"
#include "pal_error.h"
#include "api.h"

#include <linux/types.h>
typedef __kernel_pid_t pid_t;
#include <linux/stat.h>
#include <asm/stat.h>
#include <asm/fcntl.h>

#define DEVICE_OPS(handle)                              \
    ({ int _type = (handle)->dev.dev_type;              \
       (_type <= 0 || _type >= PAL_DEVICE_TYPE_BOUND) ? \
       NULL : pal_device_ops[_type];                    \
     })

enum {
    device_type_none = 0,
    device_type_term,
    PAL_DEVICE_TYPE_BOUND,
};

static struct handle_ops term_ops;

static const struct handle_ops * pal_device_ops [PAL_DEVICE_TYPE_BOUND] = {
            NULL,
            &term_ops,
        };

/* parse-device_uri scan the uri, parse the prefix of the uri and search
   for stream handler wich will open or access the device */
static int parse_device_uri (const char ** uri, const char ** type,
                             struct handle_ops ** ops)
{
    struct handle_ops * dops = NULL;
    const char * p, * u = (*uri);

    for (p = u ; (*p) && (*p) != ',' && (*p) != '/' ; p++);

    if (strpartcmp_static(u, "tty"))
        dops = &term_ops;

    if (!dops)
        return -PAL_ERROR_NOTSUPPORT;

    *uri = (*p) ? p + 1 : p;
    if (type)
        *type = u;
    if (ops)
        *ops = dops;
    return 0;
}

static inline void
dev_attrcopy (PAL_STREAM_ATTR * attr, struct stat * stat);

static int64_t char_read (PAL_HANDLE handle, uint64_t offset, uint64_t count,
                          void * buffer);
static int64_t char_write (PAL_HANDLE handle, uint64_t offset, uint64_t count,
                       const void * buffer);
static int term_attrquery (const char * type, const char * uri,
                           PAL_STREAM_ATTR * attr);
static int term_attrquerybyhdl (PAL_HANDLE hdl,
                                PAL_STREAM_ATTR * attr);

/* Method to open standard terminal */
static int open_standard_term (PAL_HANDLE * handle, const char * param,
                               int access)
{
    if (param)
        return -PAL_ERROR_NOTIMPLEMENTED;

    PAL_HANDLE hdl = malloc(HANDLE_SIZE(dev));
    SET_HANDLE_TYPE(hdl, dev);
    hdl->dev.dev_type = device_type_term;

    if (!(access & PAL_ACCESS_WRONLY)) {
        HANDLE_HDR(hdl)->flags |= RFD(0);
        hdl->dev.fd_in = 0;
    }

    if (access & (PAL_ACCESS_WRONLY|PAL_ACCESS_RDWR)) {
        HANDLE_HDR(hdl)->flags |= WFD(1);
        hdl->dev.fd_out = 1;
    }

    *handle = hdl;
    return 0;
}

/* 'open' operation for terminal stream */
static int term_open (PAL_HANDLE *handle, const char * type, const char * uri,
                      int access, int share, int create, int options)
{
    const char * term = NULL;
    const char * param = NULL;

    const char * tmp = uri;
    while (*tmp) {
        if (!term && *tmp == '/')
            term = tmp + 1;
        if (*tmp == ',') {
            param = param + 1;
            break;
        }
        tmp++;
    }

    if (term)
        return -PAL_ERROR_NOTIMPLEMENTED;

    return open_standard_term(handle, param, access);
}

static int term_close (PAL_HANDLE handle)
{
    return 0;
}

/* 'attrquery' operation for terminal stream */
static int term_attrquery (const char * type, const char * uri,
                           PAL_STREAM_ATTR * attr)
{
    attr->handle_type = pal_type_dev;
    attr->readable  = PAL_TRUE;
    attr->writeable = PAL_TRUE;
    attr->runnable  = PAL_FALSE;
    attr->pending_size = 0;
    return 0;
}

/* 'attrquery' operation for terminal stream */
static int term_attrquerybyhdl (PAL_HANDLE hdl,
                                PAL_STREAM_ATTR * attr)
{
    attr->handle_type = pal_type_dev;
    attr->readable  = (hdl->dev.fd_in  != PAL_IDX_POISON);
    attr->writeable = (hdl->dev.fd_out != PAL_IDX_POISON);
    attr->runnable  = PAL_FALSE;
    attr->pending_size = 0;
    return 0;
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
static int64_t char_read (PAL_HANDLE handle, uint64_t offset, uint64_t size,
                          void * buffer)
{
    int fd = handle->dev.fd_in;

    if (fd == PAL_IDX_POISON)
        return -PAL_ERROR_DENIED;

    if (size >= (1ULL << (sizeof(unsigned int) * 8)))
        return -PAL_ERROR_INVAL;

    return ocall_read(fd, buffer, size);
}

/* 'write' operation for character streams. */
static int64_t char_write (PAL_HANDLE handle, uint64_t offset, uint64_t size,
                           const void * buffer)
{
    int fd = handle->dev.fd_out;

    if (fd == PAL_IDX_POISON)
        return -PAL_ERROR_DENIED;

    if (size >= (1ULL << (sizeof(unsigned int) * 8)))
        return -PAL_ERROR_INVAL;

    return ocall_write(fd, buffer, size);
}

/* 'open' operation for device streams */
static int dev_open (PAL_HANDLE * handle, const char * type, const char * uri,
                     int access, int share, int create, int options)
{
    struct handle_ops * ops = NULL;
    const char * dev_type = NULL;
    int ret = 0;

    ret = parse_device_uri(&uri, &dev_type, &ops);

    if (ret < 0)
        return ret;

    if (!ops->open)
            return -PAL_ERROR_NOTSUPPORT;

    PAL_HANDLE hdl = malloc(HANDLE_SIZE(dev));
    SET_HANDLE_TYPE(hdl, dev);
    hdl->dev.fd_in  = PAL_IDX_POISON;
    hdl->dev.fd_out = PAL_IDX_POISON;
    *handle = hdl;

    return ops->open(handle, dev_type, uri,
                     access, share, create, options);
}

/* 'read' operation for device stream */
static int64_t dev_read (PAL_HANDLE handle, uint64_t offset, uint64_t size,
                         void * buffer)
{
    const struct handle_ops * ops = DEVICE_OPS(handle);

    if (!ops || !ops->read)
        return -PAL_ERROR_NOTSUPPORT;

    return ops->read(handle, offset, size, buffer);
}

/* 'write' operation for device stream */
static int64_t dev_write (PAL_HANDLE handle, uint64_t offset, uint64_t size,
                          const void * buffer)
{
    const struct handle_ops * ops = DEVICE_OPS(handle);

    if (!ops || !ops->write)
        return -PAL_ERROR_NOTSUPPORT;

    return ops->write(handle, offset, size, buffer);
}

/* 'close' operation for device streams */
static int dev_close (PAL_HANDLE handle)
{
    const struct handle_ops * ops = DEVICE_OPS(handle);

    if (ops && ops->close)
        return ops->close(handle);

    if (handle->dev.fd_in != PAL_IDX_POISON) {
        int fd = handle->dev.fd_in;
        ocall_close(fd);
    }

    if (handle->dev.fd_out != PAL_IDX_POISON) {
        int fd = handle->dev.fd_out;
        ocall_close(fd);
    }

    if (handle->file.realpath)
        free((void *) handle->file.realpath);

    return 0;
}

/* 'delete' operation for device streams */
static int dev_delete (PAL_HANDLE handle, int access)
{
    const struct handle_ops * ops = DEVICE_OPS(handle);

    if (!ops || !ops->delete)
        return -PAL_ERROR_DENIED;

    int ret = dev_close(handle);

    if (ret < 0)
        return ret;

    return ops->delete(handle, access);
}

/* 'flush' operation for device streams */
static int dev_flush (PAL_HANDLE handle)
{
    const struct handle_ops * ops = DEVICE_OPS(handle);

    if (ops && ops->flush)
        return ops->flush(handle);

    /* try to flush input stream */
    if (handle->dev.fd_in != PAL_IDX_POISON) {
        int fd = handle->dev.fd_in;
        ocall_fsync(fd);
    }

    /* if output stream exists and does not equal to input stream,
       flush output stream as well */
    if (handle->dev.fd_out != PAL_IDX_POISON &&
        handle->dev.fd_out != handle->dev.fd_in) {
        int fd = handle->dev.fd_out;
        ocall_fsync(fd);
    }

    return 0;
}

static inline void
dev_attrcopy (PAL_STREAM_ATTR * attr, struct stat * stat)
{
    attr->handle_type = pal_type_dev;
    /* readable, writable and runnable are decied by euidstataccess */
    attr->readable  = stataccess(stat, ACCESS_R);
    attr->writeable = stataccess(stat, ACCESS_W);
    attr->runnable  = stataccess(stat, ACCESS_X);
    attr->pending_size = stat->st_size;
}

/* 'attrquery' operation for device streams */
static int dev_attrquery (const char * type, const char * uri,
                          PAL_STREAM_ATTR * attr)
{
    struct handle_ops * ops = NULL;
    const char * dev_type = NULL;
    int ret = 0;

    ret = parse_device_uri(&uri, &dev_type, &ops);

    if (ret < 0)
        return ret;

    if (!ops || !ops->attrquery)
        return -PAL_ERROR_NOTSUPPORT;

    return ops->attrquery(dev_type, uri, attr);
}

/* 'attrquerybyhdl' operation for device stream */
static int dev_attrquerybyhdl (PAL_HANDLE handle,
                               PAL_STREAM_ATTR * attr)
{
    const struct handle_ops * ops = DEVICE_OPS(handle);

    if (ops && ops->attrquerybyhdl)
        return ops->attrquerybyhdl(handle, attr);

    struct stat stat_buf, * stat_in = NULL, * stat_out = NULL;
    int ret;

    attr->handle_type = pal_type_dev;

    if (handle->dev.fd_in != PAL_IDX_POISON) {
        ret = ocall_fstat(handle->dev.fd_in, &stat_buf);
        if (!ret)
            stat_in = &stat_buf;
    }

    if (handle->dev.fd_in != PAL_IDX_POISON) {
        ret = ocall_fstat(handle->dev.fd_in, &stat_buf);
        if (!ret)
            stat_out = &stat_buf;
    }

    attr->readable  = (stat_in  && stataccess(stat_in,  ACCESS_R));
    attr->writeable = (stat_in  && stataccess(stat_in,  ACCESS_W));
    attr->runnable  = (stat_out && stataccess(stat_out, ACCESS_X));
    attr->pending_size = stat_in ? stat_in->st_size :
                         (stat_out ? stat_out->st_size : 0);
    return 0;
}

static const char * dev_getrealpath (PAL_HANDLE handle)
{
    return handle->dev.realpath;
}

struct handle_ops dev_ops = {
        .getrealpath        = &dev_getrealpath,
        .open               = &dev_open,
        .read               = &dev_read,
        .write              = &dev_write,
        .close              = &dev_close,
        .delete             = &dev_delete,
        .flush              = &dev_flush,
        .attrquery          = &dev_attrquery,
        .attrquerybyhdl     = &dev_attrquerybyhdl,
    };
