/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * Simple test for file rename.
 *
 * TODO: We should cover various corner cases such as files, directories, target existing/not
 * existing, etc.
 */

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static const char message1[] = "first message\n";
static const size_t message1_len = sizeof(message1) - 1;

static const char message2[] = "second message\n";
static const size_t message2_len = sizeof(message2) - 1;

static_assert(sizeof(message1) != sizeof(message2), "the messages should have different lengths");

static int write_all(int fd, const char* str, size_t size) {
    while (size > 0) {
        ssize_t n = write(fd, str, size);
        if (n == -1 && errno == -EINTR)
            continue;
        if (n == -1)
            return -1;
        assert(n <= size);
        size -= n;
        str += n;
    }
    return 0;
}

static int read_all(int fd, char* str, size_t size) {
    while (size > 0) {
        ssize_t n = read(fd, str, size);
        if (n == -1 && errno == -EINTR)
            continue;
        if (n == -1)
            return -1;
        if (n == 0)
            break;
        assert(n <= size);
        size -= n;
        str += n;
    }
    if (size > 0) {
        warnx("read less bytes than expected");
        return -1;
    }
    return 0;
}

static void should_not_exist(const char* path) {
    struct stat statbuf;

    if (stat(path, &statbuf) == 0)
        errx(1, "%s unexpectedly exists", path);
    if (errno != ENOENT)
        err(1, "stat %s", path);
}

static void should_exist(const char* path, size_t size) {
    struct stat statbuf;

    if (stat(path, &statbuf) == -1)
        err(1, "stat %s", path);
    if (!S_ISREG(statbuf.st_mode))
        errx(1, "%s has wrong mode (%o)", path, statbuf.st_mode);
    if (statbuf.st_size != size)
        errx(1, "%s has wrong size (%lu)", path, statbuf.st_size);
}

static void should_contain(const char* path, int fd, const char* str, size_t len) {
    char* buffer = malloc(len);
    if (!buffer)
        err(1, "malloc");

    struct stat statbuf;
    if (fstat(fd, &statbuf) == -1)
        err(1, "fstat %s", path);
    if (!S_ISREG(statbuf.st_mode))
        errx(1, "%s has wrong mode (%o)", path, statbuf.st_mode);
    if (statbuf.st_size != len)
        errx(1, "%s has wrong size (%lu)", path, statbuf.st_size);

    if (lseek(fd, 0, SEEK_SET) == -1)
        err(1, "lseek %s", path);

    if (read_all(fd, buffer, len) == -1)
        errx(1, "read_all from %s failed", path);
    if (memcmp(buffer, str, len) != 0)
        errx(1, "%s has wrong content", path);

    free(buffer);
}

static int create_file(const char* path, const char* str, size_t len) {
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd == -1)
        err(1, "open %s", path);

    if (write_all(fd, str, len) == -1)
        err(1, "write_all %s", path);

    return fd;
}

static void create_file_and_close(const char* path, const char* str, size_t len) {
    int fd = create_file(path, str, len);
    if (close(fd) == -1)
        err(1, "close %s", path);
}

static void test_simple_rename(const char* path1, const char* path2) {
    printf("%s...\n", __func__);

    create_file_and_close(path1, message1, message1_len);

    if (rename(path1, path2) == -1)
        err(1, "rename");

    should_not_exist(path1);
    should_exist(path2, message1_len);

    int fd = open(path2, O_RDONLY, 0);
    if (fd == -1)
        err(1, "open %s", path2);

    should_contain(path2, fd, message1, message1_len);

    if (close(fd) == -1)
        err(1, "close %s", path2);

    if (unlink(path2) == -1)
        err(1, "unlink %s", path2);
}

static void test_rename_replace(const char* path1, const char* path2) {
    printf("%s...\n", __func__);

    create_file_and_close(path1, message1, message1_len);

    int fd = create_file(path2, message2, message2_len);

    if (fd == -1)
        err(1, "open %s", path2);

    if (rename(path1, path2) == -1)
        err(1, "rename");

    should_not_exist(path1);
    should_exist(path2, message1_len);

    should_contain(path2, fd, message2, message2_len);

    if (close(fd) == -1)
        err(1, "close %s", path2);

    if (unlink(path2) == -1)
        err(1, "unlink %s", path2);
}

static void test_rename_open_file(const char* path1, const char* path2) {
    printf("%s...\n", __func__);

    int fd = create_file(path1, message1, message1_len);

    if (rename(path1, path2) == -1)
        err(1, "rename");

    create_file_and_close(path1, message2, message2_len);

    should_contain(path2, fd, message1, message1_len);

    if (close(fd) == -1)
        err(1, "close %s", path2);

    if (unlink(path2) == -1)
        err(1, "unlink %s", path2);
}

static void test_unlink(const char* path) {
    printf("%s...\n", __func__);

    int fd1 = create_file(path, message1, message1_len);

    if (unlink(path) == -1)
        err(1, "unlink");

    should_not_exist(path);

    int fd2 = create_file(path, message2, message2_len);

    should_exist(path, message2_len);
    should_contain(path, fd1, message1, message1_len);
    should_contain(path, fd2, message2, message2_len);

    if (close(fd1) == -1)
        err(1, "close old %s", path);
    if (close(fd2) == -1)
        err(1, "close new %s", path);
    if (unlink(path) == -1)
        err(1, "unlink %s", path);
}


int main(int argc, char* argv[]) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    if (argc != 3)
        errx(1, "Usage: %s <path1> <path2>", argv[0]);

    const char* path1 = argv[1];
    const char* path2 = argv[2];

    test_simple_rename(path1, path2);
    test_rename_replace(path1, path2);
    test_rename_open_file(path1, path2);
    test_unlink(path1);
    printf("TEST OK\n");
    return 0;
}
