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
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

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

int main(int argc, char* argv[]) {
    if (argc != 3)
        errx(1, "Usage: %s <path1> <path2>", argv[0]);

    const char* path1 = argv[1];
    const char* path2 = argv[2];

    const char* message = "hello world\n";
    size_t message_len = strlen(message);

    int fd = open(path1, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd == -1)
        err(1, "open %s", path1);

    if (write_all(fd, message, message_len) == -1)
        err(1, "write_all");

    if (close(fd) == -1)
        err(1, "close %s", path1);

    /* Rename path1 to path2 */
    if (rename(path1, path2) == -1)
        err(1, "rename");

    struct stat statbuf;

    /* path1 should not exist anymore */
    if (stat(path1, &statbuf) == 0)
        errx(1, "%s unexpectedly exists", path1);
    if (errno != ENOENT)
        err(1, "stat %s", path1);

    /* path2 should have the right mode and size */
    if (stat(path2, &statbuf) == -1)
        err(1, "stat %s", path2);
    if (!S_ISREG(statbuf.st_mode))
        errx(1, "%s has wrong mode (%o)", path2, statbuf.st_mode);
    if (statbuf.st_size != message_len)
        errx(1, "%s has wrong size (%lu)", path2, statbuf.st_size);

    /* path2 should have the right content */
    fd = open(path2, O_RDONLY, 0);
    if (fd == -1)
        err(1, "open %s", path2);

    char buffer[message_len];
    if (read_all(fd, buffer, message_len) == -1)
        errx(1, "read_all");
    if (memcmp(buffer, message, message_len) != 0)
        errx(1, "%s has wrong content", path2);

    if (close(fd) == -1)
        err(1, "close %s", path2);

    /* Clean up */
    if (unlink(path2) == -1)
        err(1, "unlink");

    printf("TEST OK\n");

    return 0;
}
