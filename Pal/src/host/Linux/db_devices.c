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

    assert(0 <= access && access < PAL_ACCESS_BOUND);
    assert(WITHIN_MASK(share,   PAL_SHARE_MASK));
    assert(WITHIN_MASK(create,  PAL_CREATE_MASK));
    assert(WITHIN_MASK(options, PAL_OPTION_MASK));

    PAL_HANDLE hdl = malloc(HANDLE_SIZE(dev));
    if (!hdl)
        return -PAL_ERROR_NOMEM;

    init_handle_hdr(HANDLE_HDR(hdl), PAL_TYPE_DEV);

    if (!strcmp(uri, "tty")) {
        /* special case of "dev:tty" device which is the standard input + standard output */
        hdl->dev.nonblocking = PAL_FALSE;

        if (access == PAL_ACCESS_RDONLY) {
            HANDLE_HDR(hdl)->flags |= RFD(0);
            hdl->dev.fd = 0; /* host stdin */
        } else if (access == PAL_ACCESS_WRONLY) {
            HANDLE_HDR(hdl)->flags |= WFD(0);
            hdl->dev.fd = 1; /* host stdout */
        } else {
            assert(access == PAL_ACCESS_RDWR);
            ret = -PAL_ERROR_INVAL;
            goto fail;
        }
    } else {
        /* other devices must be opened through the host */
        hdl->dev.nonblocking = (options & PAL_OPTION_NONBLOCK) ? PAL_TRUE : PAL_FALSE;

        ret = DO_SYSCALL(open, uri, PAL_ACCESS_TO_LINUX_OPEN(access)  |
                                    PAL_CREATE_TO_LINUX_OPEN(create)  |
                                    PAL_OPTION_TO_LINUX_OPEN(options),
                         share);
        if (ret < 0) {
            ret = unix_to_pal_error(ret);
            goto fail;
        }
        hdl->dev.fd = ret;

        if (access == PAL_ACCESS_RDONLY) {
            HANDLE_HDR(hdl)->flags |= RFD(0);
        } else if (access == PAL_ACCESS_WRONLY) {
            HANDLE_HDR(hdl)->flags |= WFD(0);
        } else {
            assert(access == PAL_ACCESS_RDWR);
            HANDLE_HDR(hdl)->flags |= RFD(0) | WFD(0);
        }
    }

    *handle = hdl;
    return 0;
fail:
    free(hdl);
    return ret;
}

static int64_t dev_read(PAL_HANDLE handle, uint64_t offset, uint64_t size, void* buffer) {
    if (offset || HANDLE_HDR(handle)->type != PAL_TYPE_DEV)
        return -PAL_ERROR_INVAL;

    if (!(HANDLE_HDR(handle)->flags & RFD(0)))
        return -PAL_ERROR_DENIED;

    if (handle->dev.fd == PAL_IDX_POISON)
        return -PAL_ERROR_DENIED;

    int64_t bytes = DO_SYSCALL(read, handle->dev.fd, buffer, size);
    return bytes < 0 ? unix_to_pal_error(bytes) : bytes;
}

static int64_t dev_write(PAL_HANDLE handle, uint64_t offset, uint64_t size, const void* buffer) {
    if (offset || HANDLE_HDR(handle)->type != PAL_TYPE_DEV)
        return -PAL_ERROR_INVAL;

    if (!(HANDLE_HDR(handle)->flags & WFD(0)))
        return -PAL_ERROR_DENIED;

    if (handle->dev.fd == PAL_IDX_POISON)
        return -PAL_ERROR_DENIED;

    int64_t bytes = DO_SYSCALL(write, handle->dev.fd, buffer, size);
    return bytes < 0 ? unix_to_pal_error(bytes) : bytes;
}

static int dev_close(PAL_HANDLE handle) {
    if (HANDLE_HDR(handle)->type != PAL_TYPE_DEV)
        return -PAL_ERROR_INVAL;

    /* currently we just assign `0`/`1` FDs without duplicating, so close is a no-op for them */
    int ret = 0;
    if (handle->dev.fd != PAL_IDX_POISON && handle->dev.fd != 0 && handle->dev.fd != 1) {
        ret = DO_SYSCALL(close, handle->dev.fd);
    }
    handle->dev.fd = PAL_IDX_POISON;
    return ret < 0 ? unix_to_pal_error(ret) : 0;
}

static int dev_flush(PAL_HANDLE handle) {
    if (HANDLE_HDR(handle)->type != PAL_TYPE_DEV)
        return -PAL_ERROR_INVAL;

    if (handle->dev.fd != PAL_IDX_POISON) {
        int ret = DO_SYSCALL(fsync, handle->dev.fd);
        if (ret < 0)
            return unix_to_pal_error(ret);
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
        int ret = DO_SYSCALL(stat, uri, &stat_buf);
        if (ret < 0)
            return unix_to_pal_error(ret);

        attr->readable     = stataccess(&stat_buf, ACCESS_R);
        attr->writable     = stataccess(&stat_buf, ACCESS_W);
        attr->runnable     = stataccess(&stat_buf, ACCESS_X);
        attr->share_flags  = stat_buf.st_mode;
        attr->pending_size = stat_buf.st_size;
    }

    attr->handle_type  = PAL_TYPE_DEV;
    attr->nonblocking  = PAL_FALSE;
    return 0;
}

static int dev_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    if (HANDLE_HDR(handle)->type != PAL_TYPE_DEV)
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
        int ret = DO_SYSCALL(fstat, handle->dev.fd, &stat_buf);
        if (ret < 0)
            return unix_to_pal_error(ret);

        attr->readable     = stataccess(&stat_buf, ACCESS_R);
        attr->writable     = stataccess(&stat_buf, ACCESS_W);
        attr->runnable     = stataccess(&stat_buf, ACCESS_X);
        attr->share_flags  = stat_buf.st_mode;
        attr->pending_size = stat_buf.st_size;
    }

    attr->handle_type  = PAL_TYPE_DEV;
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
