/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Labs */

/*!
 * \file
 *
 * This file contains the implementation of `/dev/random` and `/dev/urandom` pseudo-files.
 */

#include "pal.h"
#include "shim_fs.h"
#include "shim_fs_pseudo.h"

ssize_t dev_random_read(struct shim_handle* hdl, void* buf, size_t count) {
    __UNUSED(hdl);
    int ret = DkRandomBitsRead(buf, count);

    if (ret < 0)
        return pal_to_unix_errno(ret);
    return count;
}
