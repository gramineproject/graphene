/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>

int main(int argc, char ** argv)
{
    int sv[2];

    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);

    int pid1 = fork();

    if (pid1 < 0) {
        printf("fork failed\n");
        return -1;
    }

    if (pid1 == 0) {
        close(sv[0]);
        write(sv[1], "hello world",12);
        return 0;
    }

    char buffer[20];
    int bytes;

    close(sv[1]);
    bytes = read(sv[0], buffer, 12);
    buffer[bytes] = 0;
    printf("%s\n", buffer);

    waitpid(pid1, NULL, 0);

    return 0;
}
