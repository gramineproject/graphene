/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

int main() {

    int fd = open("test.open.file", O_CREAT | O_RDWR, S_IRWXU);

    int fd2 = open("fs.manifest", O_RDONLY);

    char * buf = malloc (4096);

    int ret;
    while ((ret = read(fd2, buf, 4096)) > 0) {
        write(1, buf, ret);
        write(fd, buf, ret);
    }

    close(fd);
}
