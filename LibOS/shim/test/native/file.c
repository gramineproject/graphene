/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char ** argv)
{
    int fd1 = creat("testfile", 0600);

    if (fd1 < 0) {
        perror("creat");
        return 1;
    }

    write(fd1, "Hello World\n", 12);
    close(fd1);

    int fd2 = open("testfile", O_RDONLY, 0600);

    if (fd2 < 0) {
        perror("open without O_CREAT");
        return 1;
    }

    char buffer[20];
    int bytes = read(fd2, buffer, 20);

    if (bytes < 0) {
        perror("read");
        return 1;
    }

    buffer[11] = 0;
    printf("read from file: %s\n", buffer);
    close(fd2);
    unlink("testfile");

    int fd3 = open("testfile", O_RDWR|O_CREAT|O_EXCL, 0600);

    if (fd3 < 0) {
        perror("open with O_CREAT and O_EXCL");
        return 1;
    }

    close(fd3);
    unlink("testfile");
    return 0;
}
