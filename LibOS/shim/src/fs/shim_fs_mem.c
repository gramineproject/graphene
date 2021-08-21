/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

#include "api.h"
#include "shim_fs.h"
#include "shim_fs_mem.h"

static int mem_file_resize(struct shim_mem_file* mem, size_t buf_size) {
    char* buf = malloc(buf_size);
    if (!buf)
        return -ENOMEM;

    memcpy(buf, mem->buf, MIN(buf_size, (size_t)mem->size));
    free(mem->buf);
    mem->buf = buf;
    mem->buf_size = buf_size;
    return 0;
}

void mem_file_init(struct shim_mem_file* mem, char* data, size_t size) {
    assert(!OVERFLOWS(file_off_t, size));

    mem->buf = data;
    mem->buf_size = size;
    mem->size = size;
}

void mem_file_destroy(struct shim_mem_file* mem) {
    free(mem->buf);
}

ssize_t mem_file_read(struct shim_mem_file* mem, file_off_t pos_start, void* buf, size_t size) {
    assert(pos_start >= 0);

    file_off_t pos_end;
    if (__builtin_add_overflow(pos_start, size, &pos_end) || pos_end > mem->size)
        pos_end = mem->size;

    size = pos_end >= pos_start ? pos_end - pos_start : 0;
    if (size > 0)
        memcpy(buf, mem->buf + pos_start, size);
    return size;
}

ssize_t mem_file_write(struct shim_mem_file* mem, file_off_t pos_start, const void* buf,
                       size_t size) {
    assert(pos_start >= 0);

    file_off_t pos_end;
    if (__builtin_add_overflow(pos_start, size, &pos_end))
        return -EFBIG;

    if (OVERFLOWS(size_t, pos_end))
        return -EFBIG;

    if (size > 0) {
        if ((size_t)pos_end > mem->buf_size) {
            size_t buf_size = MAX(mem->buf_size, 1U);
            while (buf_size < (size_t)pos_end)
                if (__builtin_mul_overflow(buf_size, 2, &buf_size))
                    return -EFBIG;

            int ret = mem_file_resize(mem, buf_size);
            if (ret < 0)
                return ret;
        }
        assert((size_t)pos_end <= mem->buf_size);
        if (pos_end > mem->size)
            mem->size = pos_end;
        memcpy(mem->buf + pos_start, buf, size);
    }

    return size;
}

int mem_file_truncate(struct shim_mem_file* mem, file_off_t size) {
    assert(size >= 0);

    if (OVERFLOWS(size_t, size))
        return -EFBIG;

    int ret = mem_file_resize(mem, size);
    if (ret < 0)
        return ret;
    mem->size = size;
    return 0;
}

int mem_file_poll(struct shim_mem_file* mem, file_off_t pos, int poll_type) {
    int ret = 0;
    if ((poll_type & FS_POLL_RD) && (pos < mem->size))
        ret |= FS_POLL_RD;
    if (poll_type & FS_POLL_WR)
        ret |= FS_POLL_WR;
    return ret;
}
