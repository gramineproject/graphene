/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>

#define TESTFILE "testfile"

int main(int argc, char ** argv)
{
    int ret = 0, fd;

    if ((ret = creat(TESTFILE, 0600)) < 0) {
        perror("creat");
        exit(1);
    }

    fd = ret;

    if ((ret = write(fd, "Hello World", 11)) < 0) {
        perror("write");
        exit(1);
    }

    close(fd);

    if ((ret = rename(TESTFILE, TESTFILE ".new")) < 0) {
        perror("rename");
        exit(1);
    }

    if ((ret = open(TESTFILE ".new", O_RDONLY)) < 0) {
        perror("open");
        exit(1);
    }

    fd = ret;

    char buffer[12];

    if ((ret = read(fd, buffer, 11)) < 0) {
        perror("read");
        exit(1);
    }

    buffer[11] = 0;
    printf("%s\n", buffer);

    close(fd);

    if ((ret = unlink(TESTFILE ".new")) < 0) {
        perror("unlink");
        exit(1);
    }

    return 0;
}
