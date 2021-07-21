/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains code for implementation of 'str' filesystem. It is used by pseudo filesystems
 * (/proc, /dev, /sys) and by tmpfs.
 */

#include <asm/fcntl.h>
#include <asm/mman.h>
#include <asm/unistd.h>
#include <errno.h>
#include <linux/fcntl.h>

#include "pal.h"
#include "pal_error.h"
#include "shim_fs.h"
#include "shim_internal.h"

int str_open(struct shim_handle* hdl, struct shim_dentry* dent, int flags) {
    struct shim_str_data* data = dent->data;

    /* when str file is opened, it must have non-NULL `data` field */
    if (!dent->data)
        return -ENOENT;

    REF_INC(data->ref_count);

    hdl->type = TYPE_STR;

    /* note that if file was just created, then `str` and `len` are guaranteed to be NULL
     * and zero */
    hdl->info.str.data = data;
    hdl->info.str.ptr = data->str;
    if (flags & O_APPEND)
        hdl->info.str.ptr += data->len;

    hdl->dentry = dent;
    hdl->flags = flags;

    return 0;
}

int str_dput(struct shim_dentry* dent) {
    struct shim_str_data* data = dent->data;

    if (!data || REF_DEC(data->ref_count) > 1)
        return 0;

    if (data->str) {
        free(data->str);
        data->str = NULL;
    }

    data->len      = 0;
    data->buf_size = 0;

    free(dent->data);
    dent->data = NULL;
    return 0;
}

int str_close(struct shim_handle* hdl) {
    assert(hdl->type == TYPE_STR);

    if (hdl->flags & (O_WRONLY | O_RDWR)) {
        int ret = str_flush(hdl);

        if (ret < 0)
            return ret;
    }

    str_dput(hdl->dentry);

    if (hdl->info.str.data) {
        free(hdl->info.str.data->str);
        free(hdl->info.str.data);
        hdl->info.str.data = NULL;
    }

    return 0;
}

ssize_t str_read(struct shim_handle* hdl, void* buf, size_t count) {
    ssize_t ret = 0;

    if (!(hdl->acc_mode & MAY_READ)) {
        ret = -EACCES;
        goto out;
    }

    assert(hdl->type == TYPE_STR);
    struct shim_str_handle* strhdl = &hdl->info.str;

    assert(hdl->dentry);
    assert(strhdl->data);

    struct shim_str_data* data = strhdl->data;

    if (!data->str) {
        log_warning("str_read: str_data has no str");
        ret = 0;
        goto out;
    }

    if (!strhdl->ptr)
        strhdl->ptr = data->str;

    off_t offset  = strhdl->ptr - data->str;

    if (data->len <= offset) {
        ret = 0;
        goto out;
    }

    size_t remain = data->len - offset;

    if (count >= remain) {
        memcpy(buf, strhdl->ptr, remain);
        strhdl->ptr += remain;

        ret = remain;
        goto out;
    }

    memcpy(buf, strhdl->ptr, count);
    strhdl->ptr += count;

    ret = count;

out:
    return ret;
}

static ssize_t str_maybe_expand_buf(struct shim_str_handle* strhdl, size_t size) {
    struct shim_str_data* data = strhdl->data;

    if (!data->str || size > data->buf_size) {
        size_t new_size = 0;

        if (data->str) {
            new_size = data->buf_size ?: 1;

            while (size > new_size) {
                new_size *= 2;
            }
        } else {
            new_size = size;
        }

        char* new_data_str = calloc(1, new_size);
        if (!new_data_str)
            return -ENOMEM;

        if (data->str) {
            memcpy(new_data_str, data->str, data->len);
            free(data->str);
        }

        strhdl->ptr    = new_data_str + (strhdl->ptr - data->str);
        data->str      = new_data_str;
        data->buf_size = new_size;
    }
    return 0;
}

ssize_t str_write(struct shim_handle* hdl, const void* buf, size_t count) {
    ssize_t ret = 0;
    if (!(hdl->acc_mode & MAY_WRITE))
        return -EACCES;

    struct shim_str_handle* strhdl = &hdl->info.str;
    assert(strhdl->data);
    struct shim_str_data* data = strhdl->data;

    ret = str_maybe_expand_buf(strhdl, strhdl->ptr - data->str + count);
    if (ret < 0)
        return ret;

    memcpy(strhdl->ptr, buf, count);

    strhdl->ptr += count;
    data->dirty = true;
    if (strhdl->ptr >= data->str + data->len)
        data->len = strhdl->ptr - data->str;

    return count;
}

off_t str_seek(struct shim_handle* hdl, off_t offset, int whence) {
    struct shim_str_handle* strhdl = &hdl->info.str;

    assert(hdl->dentry);
    assert(strhdl->data);

    struct shim_str_data* data = strhdl->data;

    switch (whence) {
        case SEEK_SET:
            if (offset < 0)
                return -EINVAL;
            strhdl->ptr = data->str + offset;
            break;

        case SEEK_CUR:
            if (strhdl->ptr + offset < data->str)
                return -EINVAL;
            strhdl->ptr += offset;
            break;

        case SEEK_END:
            if (data->len + offset < 0)
                return -EINVAL;
            strhdl->ptr = data->str + data->len + offset;
            break;
    }

    return strhdl->ptr - data->str;
}

int str_flush(struct shim_handle* hdl) {
    struct shim_str_handle* strhdl = &hdl->info.str;

    assert(hdl->dentry);
    assert(strhdl->data);

    struct shim_str_data* data = strhdl->data;

    if (!data->dirty)
        return 0;

    if (!data->modify)
        return -EACCES;

    return data->modify(hdl);
}

int str_truncate(struct shim_handle* hdl, off_t len) {
    int ret = 0;

    if (!(hdl->acc_mode & MAY_WRITE))
        return -EACCES;

    struct shim_str_handle* strhdl = &hdl->info.str;

    assert(strhdl->data);

    struct shim_str_data* data = strhdl->data;
    if (!data->str && len == 0)
        return 0;

    ret = str_maybe_expand_buf(strhdl, (size_t)len);
    if (ret < 0)
        return ret;

    data->len   = len;
    data->dirty = true;
    return ret;
}

int str_poll(struct shim_handle* hdl, int poll_type) {
    assert(hdl->type == TYPE_STR);

    struct shim_str_handle* strhdl = &hdl->info.str;
    struct shim_str_data* data = strhdl->data;
    assert(data);

    int ret = 0;
    if (poll_type & FS_POLL_RD) {
        if (data->len > 0) {
            assert(data->str);
            if (!strhdl->ptr || strhdl->ptr < (data->str + data->len))
                ret |= FS_POLL_RD;
        }
    }
    if (poll_type & FS_POLL_WR)
        ret |= FS_POLL_WR;

    return ret;
}

struct shim_fs_ops str_fs_ops = {
    .close    = &str_close,
    .read     = &str_read,
    .write    = &str_write,
    .seek     = &str_seek,
    .flush    = &str_flush,
    .truncate = &str_truncate,
    .poll     = &str_poll,
};

struct shim_d_ops str_d_ops = {
    .open = &str_open,
    .dput = &str_dput,
};
