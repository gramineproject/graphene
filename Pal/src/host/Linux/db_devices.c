/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */
/* Copyright (C) 2020 Intel Labs */

/*
 * Operations to handle devices (with special case of "dev:tty" which is stdin/stdout).
 *
 * TODO: Some devices allow lseek() but typically with device-specific semantics. Graphene currently
 *       emulates lseek() completely in LibOS layer, thus seeking at PAL layer cannot be correctly
 *       implemented (without device-specific changes to LibOS layer).
 */

#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_flags_conv.h"
#include "pal_internal.h"
#include "pal_linux.h"

static int dev_open(PAL_HANDLE* handle, const char* type, const char* uri, int access, int share,
                    int create, int options) {
    int ret;
    __UNUSED(share);
    __UNUSED(create);
    __UNUSED(options);

    if (strcmp(type, URI_TYPE_DEV))
        return -PAL_ERROR_INVAL;

    assert(WITHIN_MASK(access,  PAL_ACCESS_MASK));
    assert(WITHIN_MASK(share,   PAL_SHARE_MASK));
    assert(WITHIN_MASK(create,  PAL_CREATE_MASK));
    assert(WITHIN_MASK(options, PAL_OPTION_MASK));

    PAL_HANDLE hdl = malloc(HANDLE_SIZE(dev));
    if (!hdl)
        return -PAL_ERROR_NOMEM;

    SET_HANDLE_TYPE(hdl, dev);

    if (!strcmp(uri, "tty")) {
        /* special case of "dev:tty" device which is the standard input + standard output */
        hdl->dev.nonblocking = PAL_FALSE;

        if (access & PAL_ACCESS_RDWR) {
            ret = -PAL_ERROR_INVAL;
            goto fail;
        } else if (access & PAL_ACCESS_WRONLY) {
            HANDLE_HDR(hdl)->flags |= WFD(0);
            hdl->dev.fd = 1; /* host stdout */
        } else {
            HANDLE_HDR(hdl)->flags |= RFD(0);
            hdl->dev.fd = 0; /* host stdin */
        }
    } else {
        /* other devices must be opened through the host */
        hdl->dev.nonblocking = (options & PAL_OPTION_NONBLOCK) ? PAL_TRUE : PAL_FALSE;

        ret = INLINE_SYSCALL(open, 3, uri, PAL_ACCESS_TO_LINUX_OPEN(access)  |
                                           PAL_CREATE_TO_LINUX_OPEN(create)  |
                                           PAL_OPTION_TO_LINUX_OPEN(options),
                             share);
        if (IS_ERR(ret)) {
            ret = unix_to_pal_error(ERRNO(ret));
            goto fail;
        }
        hdl->dev.fd = ret;

        if (access & PAL_ACCESS_RDWR) {
            HANDLE_HDR(hdl)->flags |= RFD(0) | WFD(0);
        } else if (access & PAL_ACCESS_WRONLY) {
            HANDLE_HDR(hdl)->flags |= WFD(0);
        } else {
            HANDLE_HDR(hdl)->flags |= RFD(0);
        }
    }

    *handle = hdl;
    return 0;
fail:
    free(hdl);
    return ret;
}

static int64_t dev_read(PAL_HANDLE handle, uint64_t offset, uint64_t size, void* buffer) {
    if (offset || !IS_HANDLE_TYPE(handle, dev))
        return -PAL_ERROR_INVAL;

    if (!(HANDLE_HDR(handle)->flags & RFD(0)))
        return -PAL_ERROR_DENIED;

    if (handle->dev.fd == PAL_IDX_POISON)
        return -PAL_ERROR_DENIED;

    int64_t bytes = INLINE_SYSCALL(read, 3, handle->dev.fd, buffer, size);
    return IS_ERR(bytes) ? unix_to_pal_error(ERRNO(bytes)) : bytes;
}

static int64_t dev_write(PAL_HANDLE handle, uint64_t offset, uint64_t size, const void* buffer) {
    if (offset || !IS_HANDLE_TYPE(handle, dev))
        return -PAL_ERROR_INVAL;

    if (!(HANDLE_HDR(handle)->flags & WFD(0)))
        return -PAL_ERROR_DENIED;

    if (handle->dev.fd == PAL_IDX_POISON)
        return -PAL_ERROR_DENIED;

    int64_t bytes = INLINE_SYSCALL(write, 3, handle->dev.fd, buffer, size);
    return IS_ERR(bytes) ? unix_to_pal_error(ERRNO(bytes)) : bytes;
}

static int dev_close(PAL_HANDLE handle) {
    if (!IS_HANDLE_TYPE(handle, dev))
        return -PAL_ERROR_INVAL;

    /* currently we just assign `0`/`1` FDs without duplicating, so close is a no-op for them */
    int ret = 0;
    if (handle->dev.fd != PAL_IDX_POISON && handle->dev.fd != 0 && handle->dev.fd != 1) {
        ret = INLINE_SYSCALL(close, 1, handle->dev.fd);
    }
    handle->dev.fd = PAL_IDX_POISON;
    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : 0;
}

static int dev_flush(PAL_HANDLE handle) {
    if (!IS_HANDLE_TYPE(handle, dev))
        return -PAL_ERROR_INVAL;

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
        return -PAL_ERROR_INVAL;

    if (!strcmp(uri, "tty")) {
        /* special case of "dev:tty" device which is the standard input + standard output */
        attr->readable     = PAL_TRUE; /* we don't know if it's stdin/stdout so simply return true */
        attr->writable     = PAL_TRUE; /* we don't know if it's stdin/stdout so simply return true */
        attr->runnable     = PAL_FALSE;
        attr->share_flags  = 0;
        attr->pending_size = 0;
    } else {
        /* other devices must query the host */
        struct stat stat_buf;
        int ret = INLINE_SYSCALL(stat, 2, uri, &stat_buf);
        if (IS_ERR(ret))
            return unix_to_pal_error(ERRNO(ret));

        attr->readable     = stataccess(&stat_buf, ACCESS_R);
        attr->writable     = stataccess(&stat_buf, ACCESS_W);
        attr->runnable     = stataccess(&stat_buf, ACCESS_X);
        attr->share_flags  = stat_buf.st_mode;
        attr->pending_size = stat_buf.st_size;
    }

    attr->handle_type  = pal_type_dev;
    attr->nonblocking  = PAL_FALSE;
    return 0;
}

static int dev_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    if (!IS_HANDLE_TYPE(handle, dev))
        return -PAL_ERROR_INVAL;

    if (handle->dev.fd == 0 || handle->dev.fd == 1) {
        /* special case of "dev:tty" device which is the standard input + standard output */
        attr->readable     = HANDLE_HDR(handle)->flags & RFD(0);
        attr->writable     = HANDLE_HDR(handle)->flags & WFD(0);
        attr->runnable     = PAL_FALSE;
        attr->share_flags  = 0;
        attr->pending_size = 0;
    } else {
        /* other devices must query the host */
        struct stat stat_buf;
        int ret = INLINE_SYSCALL(fstat, 2, handle->dev.fd, &stat_buf);
        if (IS_ERR(ret))
            return unix_to_pal_error(ERRNO(ret));

        attr->readable     = stataccess(&stat_buf, ACCESS_R);
        attr->writable     = stataccess(&stat_buf, ACCESS_W);
        attr->runnable     = stataccess(&stat_buf, ACCESS_X);
        attr->share_flags  = stat_buf.st_mode;
        attr->pending_size = stat_buf.st_size;
    }

    attr->handle_type  = pal_type_dev;
    attr->nonblocking  = handle->dev.nonblocking;
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
