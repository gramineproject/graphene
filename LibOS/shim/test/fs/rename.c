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

#include <err.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"

int main(int argc, char* argv[]) {
    if (argc != 3)
        fatal_error("Usage: %s <path1> <path2>\n", argv[0]);

    const char* path1 = argv[1];
    const char* path2 = argv[2];

    const char* message = "hello world\n";
    size_t message_len = strlen(message);

    int fd = open_output_fd(path1, /*rdwr=*/false);
    write_fd(path1, fd, message, message_len);
    close_fd(path1, fd);

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
    char buffer[message_len];
    fd = open_input_fd(path2);
    read_fd(path2, fd, buffer, message_len);
    if (memcmp(buffer, message, message_len) != 0)
        errx(1, "%s has wrong content", path2);

    /* Clean up */
    if (unlink(path2) == -1)
        err(1, "unlink");

    printf("TEST OK\n");

    return 0;
}
