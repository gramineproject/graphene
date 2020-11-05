/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Operations to handle devices (currently only "dev:tty" which is stdin/stdout).
 */

#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"

static int dev_open(PAL_HANDLE* handle, const char* type, const char* uri, int access, int share,
                    int create, int options) {
    __UNUSED(share);
    __UNUSED(create);
    __UNUSED(options);

    if (strcmp(type, URI_TYPE_DEV))
        return -PAL_ERROR_INVAL;

    /* currently support only "dev:tty" device which is the standard input + standard output */
    if (strcmp(uri, "tty"))
        return -PAL_ERROR_INVAL;

    /* "dev:tty" device can only be opened either for read (stdin) or for write (stdout) */
    if (access & PAL_ACCESS_RDWR)
        return -PAL_ERROR_INVAL;

    assert(WITHIN_MASK(access,  PAL_ACCESS_MASK));
    assert(WITHIN_MASK(share,   PAL_SHARE_MASK));
    assert(WITHIN_MASK(create,  PAL_CREATE_MASK));
    assert(WITHIN_MASK(options, PAL_OPTION_MASK));

    PAL_HANDLE hdl = malloc(HANDLE_SIZE(dev));
    if (!hdl)
        return -PAL_ERROR_NOMEM;

    SET_HANDLE_TYPE(hdl, dev);

    if (access & PAL_ACCESS_WRONLY) {
        HANDLE_HDR(hdl)->flags |= WFD(0);
        hdl->dev.fd = 1; /* host stdout */
    } else {
        HANDLE_HDR(hdl)->flags |= RFD(0);
        hdl->dev.fd = 0; /* host stdin */
    }

    *handle = hdl;
    return 0;
}

static int64_t dev_read(PAL_HANDLE handle, uint64_t offset, uint64_t size, void* buffer) {
    if (offset)
        return -PAL_ERROR_INVAL;

    if (!IS_HANDLE_TYPE(handle, dev))
        return -PAL_ERROR_NOTCONNECTION;

    if (!(HANDLE_HDR(handle)->flags & RFD(0)))
        return -PAL_ERROR_DENIED;

    int64_t bytes = INLINE_SYSCALL(read, 3, handle->dev.fd, buffer, size);
    return IS_ERR(bytes) ? unix_to_pal_error(ERRNO(bytes)) : bytes;
}

static int64_t dev_write(PAL_HANDLE handle, uint64_t offset, uint64_t size, const void* buffer) {
    if (offset)
        return -PAL_ERROR_INVAL;

    if (!IS_HANDLE_TYPE(handle, dev))
        return -PAL_ERROR_NOTCONNECTION;

    if (!(HANDLE_HDR(handle)->flags & WFD(0)))
        return -PAL_ERROR_DENIED;

    int64_t bytes = INLINE_SYSCALL(write, 3, handle->dev.fd, buffer, size);
    return IS_ERR(bytes) ? unix_to_pal_error(ERRNO(bytes)) : bytes;
}

static int dev_close(PAL_HANDLE handle) {
    if (!IS_HANDLE_TYPE(handle, dev))
        return -PAL_ERROR_NOTCONNECTION;

    if (handle->dev.fd != PAL_IDX_POISON) {
        int ret = INLINE_SYSCALL(close, 1, handle->dev.fd);
        if (IS_ERR(ret))
            return unix_to_pal_error(ERRNO(ret));
        handle->dev.fd = PAL_IDX_POISON;
    }
    return 0;
}

static int dev_flush(PAL_HANDLE handle) {
    if (!IS_HANDLE_TYPE(handle, dev))
        return -PAL_ERROR_NOTCONNECTION;

    if (handle->dev.fd != PAL_IDX_POISON) {
        int ret = INLINE_SYSCALL(fsync, 1, handle->dev.fd);
        if (IS_ERR(ret))
            return unix_to_pal_error(ERRNO(ret));
    }
    return 0;
}

static int dev_attrquery(const char* type, const char* uri, PAL_STREAM_ATTR* attr) {
    __UNUSED(uri);

    if (strcmp(type, URI_TYPE_DEV))
        return -PAL_ERROR_NOTCONNECTION;

    /* currently support only "dev:tty" device which is the standard input + standard output */
    if (strcmp(uri, "tty"))
        return -PAL_ERROR_INVAL;

    attr->handle_type  = pal_type_dev;
    attr->readable     = PAL_TRUE; /* we don't know if it's stdin/stdout so simply return true */
    attr->writable     = PAL_TRUE; /* we don't know if it's stdin/stdout so simply return true */
    attr->runnable     = PAL_FALSE;
    attr->pending_size = 0;
    return 0;
}

static int dev_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    if (!IS_HANDLE_TYPE(handle, dev))
        return -PAL_ERROR_NOTCONNECTION;

    attr->handle_type  = pal_type_dev;
    attr->readable     = HANDLE_HDR(handle)->flags & RFD(0);
    attr->writable     = HANDLE_HDR(handle)->flags & WFD(0);
    attr->runnable     = PAL_FALSE;
    attr->pending_size = 0;
    return 0;
}

struct handle_ops g_dev_ops = {
    .open           = &dev_open,
    .read           = &dev_read,
    .write          = &dev_write,
    .close          = &dev_close,
    .flush          = &dev_flush,
    .attrquery      = &dev_attrquery,
    .attrquerybyhdl = &dev_attrquerybyhdl,
};
