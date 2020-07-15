/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Labs */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define INPUT_FILENAME "files/input.txt"

int main(int argc, char** argv) {
    char* secret = getenv("SECRET_PROVISION_SECRET_STRING");
    if (!secret) {
        fprintf(stderr, "did not receive protected files master key!\n");
        return 1;
    }

    printf("--- Received protected files master key = '%s' ---\n", secret);

    int fd = open(INPUT_FILENAME, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "[error] cannot open '" INPUT_FILENAME "'\n");
        return 1;
    }

    char buf[1024] = {0};
    ssize_t bytes_read = 0;
    while (1) {
        ssize_t ret = read(fd, buf + bytes_read, sizeof(buf) - bytes_read);
        if (ret > 0) {
            bytes_read += ret;
        } else if (ret == 0) {
            /* end of file */
            break;
        } else if (errno == EAGAIN || errno == EINTR) {
            continue;
        } else {
            fprintf(stderr, "[error] cannot read '" INPUT_FILENAME "'\n");
            close(fd);
            return 1;
        }
    }

    int ret = close(fd);
    if (ret < 0) {
        fprintf(stderr, "[error] cannot close '" INPUT_FILENAME "'\n");
        return 1;
    }

    printf("--- Read from protected file: '%s' ---\n", buf);
    return 0;
}
