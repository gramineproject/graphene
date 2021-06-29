/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/* This test checks large file sizes and offsets that overflow 32-bit integers. */

#define _GNU_SOURCE
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define TEST_FILE "tmp/large_file"

static_assert(sizeof(off_t) == 8, "this test is for 64-bit off_t");

static off_t test_lengths[] = {
    // around 2 GB (limit of 32-bit signed int)
    0x7FFFFFFF,
    0x80000001,
    // around 4 GB (limit of 32-bit unsigned int)
    0xFFFFFFFF,
    0x100000001,
    0,
};

static void try_seek(int fd, off_t offset, int whence, off_t expected) {
    off_t result = lseek(fd, offset, whence);
    if (result < 0)
        err(1, "lseek %ld %d: %ld", offset, whence, result);
    if (result != expected)
        errx(1, "got %lx, expected %lx", offset, expected);
}

int main(void) {
    setbuf(stdout, NULL);

    FILE *fp = fopen(TEST_FILE, "a+");
    if (!fp)
        err(1, "fopen");

    int fd = fileno(fp);
    int ret;

    for (unsigned int i = 0; test_lengths[i] != 0; i++) {
        off_t length = test_lengths[i];
        printf("testing length 0x%lx\n", length);

        /* Resize the file */
        ret = ftruncate(fd, length);
        if (ret < 0)
            err(1, "ftruncate");

        /* Check file size */
        struct stat st;
        if (stat(TEST_FILE, &st) < 0)
            err(1, "stat");
        if (st.st_size != length)
            errx(1, "stat: got 0x%lx, expected 0x%lx", st.st_size, length);

        /* Seek to end - 1 */
        try_seek(fd, -1, SEEK_END, length - 1);

        /* Read a single byte, check position */
        char c;
        do {
            ret = read(fd, &c, 1);
        } while (ret < 0 && errno == -EINTR);
        if (ret != 1)
            errx(1, "read %d bytes, expected %d", ret, 1);
        if (c != 0)
            errx(1, "read byte %d, expected %d", (int)c, 0);
        try_seek(fd, 0, SEEK_CUR, length);

        /* Seek to 0 and then back to length by providing large offsets */
        try_seek(fd, -length, SEEK_END, 0);
        try_seek(fd, length, SEEK_SET, length);
    }

    if (fclose(fp) == EOF)
        err(1, "fclose");

    if (unlink(TEST_FILE) < 0)
        err(1, "unlink");

    printf("TEST OK\n");
    return 0;
}
