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
 * shim_wrapper.c
 *
 * Implementation of system call "readv" and "writev".
 */

#include <errno.h>
#include <pal.h>
#include <pal_error.h>
#include <shim_fs.h>
#include <shim_handle.h>
#include <shim_internal.h>
#include <shim_table.h>
#include <shim_utils.h>

ssize_t shim_do_readv(int fd, const struct iovec* vec, int vlen) {
    if (!vec || test_user_memory((void*)vec, sizeof(*vec) * vlen, false))
        return -EINVAL;

    for (int i = 0; i < vlen; i++) {
        if (vec[i].iov_base) {
            if (vec[i].iov_base + vec[i].iov_len <= vec[i].iov_base)
                return -EINVAL;
            if (test_user_memory(vec[i].iov_base, vec[i].iov_len, true))
                return -EFAULT;
        }
    }

    struct shim_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    int ret = 0;

    if (!(hdl->acc_mode & MAY_READ) || !hdl->fs || !hdl->fs->fs_ops || !hdl->fs->fs_ops->read) {
        ret = -EACCES;
        goto out;
    }

    ssize_t bytes = 0;

    for (int i = 0; i < vlen; i++) {
        int b_vec;

        if (!vec[i].iov_base)
            continue;

        b_vec = hdl->fs->fs_ops->read(hdl, vec[i].iov_base, vec[i].iov_len);
        if (b_vec < 0) {
            ret = bytes ?: b_vec;
            goto out;
        }

        bytes += b_vec;
    }

    ret = bytes;
out:
    put_handle(hdl);
    return ret;
}

/*
 * Writev can not be implemented as write because :
 * writev() has the same requirements as write() with respect to write requests
 * of <= PIPE_BUF bytes to a pipe or FIFO: no interleaving and no partial
 * writes. Neither of these can be guaranteed in the general case if writev()
 * simply calls write() for each struct iovec.
 */

/*
 * The problem here is that we have to gaurantee Atomic writev
 *
 * Upon successful completion, writev() shall return the number of bytes
 * actually written. Otherwise, it shall return a value of -1, the file-pointer
 * shall remain unchanged, and errno shall be set to indicate an error
 */
ssize_t shim_do_writev(int fd, const struct iovec* vec, int vlen) {
    if (!vec || test_user_memory((void*)vec, sizeof(*vec) * vlen, false))
        return -EINVAL;

    for (int i = 0; i < vlen; i++) {
        if (vec[i].iov_base) {
            if (vec[i].iov_base + vec[i].iov_len < vec[i].iov_base)
                return -EINVAL;
            if (test_user_memory(vec[i].iov_base, vec[i].iov_len, false))
                return -EFAULT;
        }
    }

    struct shim_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    int ret = 0;

    if (!(hdl->acc_mode & MAY_WRITE) || !hdl->fs || !hdl->fs->fs_ops || !hdl->fs->fs_ops->write) {
        ret = -EACCES;
        goto out;
    }

    ssize_t bytes = 0;

    for (int i = 0; i < vlen; i++) {
        int b_vec;

        if (!vec[i].iov_base)
            continue;

        b_vec = hdl->fs->fs_ops->write(hdl, vec[i].iov_base, vec[i].iov_len);
        if (b_vec < 0) {
            ret = bytes ?: b_vec;
            goto out;
        }

        bytes += b_vec;
    }

    ret = bytes;
out:
    put_handle(hdl);
    return ret;
}
