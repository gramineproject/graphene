/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

#include <stdint.h>

#include "shim_fs.h"

int generic_seek(file_off_t pos, file_off_t size, file_off_t offset, int origin,
                 file_off_t* out_pos) {
    assert(pos >= 0);
    assert(size >= 0);

    switch (origin) {
        case SEEK_SET:
            pos = offset;
            break;

        case SEEK_CUR:
            if (__builtin_add_overflow(pos, offset, &pos))
                return -EOVERFLOW;
            break;

        case SEEK_END:
            if (__builtin_add_overflow(size, offset, &pos))
                return -EOVERFLOW;
            break;

        default:
            return -EINVAL;
    }

    if (pos < 0)
        return -EINVAL;

    *out_pos = pos;
    return 0;
}
