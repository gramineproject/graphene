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
 * fs.c
 *
 * This file contains codes for implementation of 'str' filesystem.
 */

#include <asm/fcntl.h>
#include <asm/mman.h>
#include <asm/prctl.h>
#include <asm/unistd.h>
#include <errno.h>
#include <linux/fcntl.h>
#include <linux/stat.h>
#include <pal.h>
#include <pal_error.h>
#include <shim_fs.h>
#include <shim_internal.h>
#include <shim_profile.h>

int str_open(struct shim_handle* hdl, struct shim_dentry* dent, int flags) {
    struct shim_str_data* data = dent->data;

    /* when str file is opened, it must have a data */
    if (!dent->data)
        return -ENOENT;

    REF_INC(data->ref_count);

    hdl->dentry = dent;
    hdl->flags  = flags;

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

    struct shim_str_handle* strhdl = &hdl->info.str;

    assert(hdl->dentry);
    assert(strhdl->data);

    struct shim_str_data* data = strhdl->data;

    if (!data->str) {
        debug("str_data has no str\n");
        ret = -EACCES;
        goto out;
    }

    if (!strhdl->ptr)
        strhdl->ptr = data->str;

    off_t offset  = strhdl->ptr - data->str;
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

ssize_t str_write(struct shim_handle* hdl, const void* buf, size_t count) {
    if (!(hdl->acc_mode & MAY_WRITE))
        return -EACCES;

    struct shim_str_handle* strhdl = &hdl->info.str;

    assert(hdl->dentry);
    assert(strhdl->data);

    struct shim_str_data* data = strhdl->data;

    if (!data->str || strhdl->ptr + count > data->str + data->buf_size) {
        int newlen = 0;

        if (data->str) {
            newlen = data->buf_size * 2;

            while (strhdl->ptr + count > data->str + newlen) {
                newlen *= 2;
            }
        } else {
            newlen = count;
        }

        char* newbuf = malloc(newlen);
        if (!newbuf)
            return -ENOMEM;

        if (data->str) {
            memcpy(newbuf, data->str, data->len);
            free(data->str);
        }

        strhdl->ptr    = newbuf + (strhdl->ptr - data->str);
        data->str      = newbuf;
        data->buf_size = newlen;
    }

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
            strhdl->ptr = data->str;
            if (strhdl->ptr > data->str + data->len)
                strhdl->ptr = data->str + data->len;
            break;

        case SEEK_CUR:
            if (offset >= 0) {
                strhdl->ptr += offset;
                if (strhdl->ptr > data->str + data->len)
                    strhdl->ptr = data->str + data->len;
            } else {
                strhdl->ptr -= offset;
                if (strhdl->ptr < data->str)
                    strhdl->ptr = data->str;
            }
            break;

        case SEEK_END:
            if (offset < 0)
                return -EINVAL;
            strhdl->ptr = data->str + data->len - offset;
            if (strhdl->ptr < data->str)
                strhdl->ptr = data->str;
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

struct shim_fs_ops str_fs_ops = {
    .close = &str_close,
    .read  = &str_read,
    .write = &str_write,
    .seek  = &str_seek,
    .flush = &str_flush,
};

struct shim_d_ops str_d_ops = {
    .open = &str_open,
    .dput = &str_dput,
};
