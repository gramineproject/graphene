/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

int main(int argc, char ** argv)
{
    int pipes[2];

    pipe(pipes);

    int pid1 = fork();

    if (pid1 < 0) {
        printf("fork failed\n");
        return -1;
    }

    if (pid1 == 0) {
        close(pipes[0]);
        write(pipes[1], "hello world",12);
        return 0;
    }

    char buffer[20];
    int bytes;

    close(pipes[1]);
    bytes = read(pipes[0], buffer, 12);
    buffer[bytes] = 0;
    printf("%s\n", buffer);

    waitpid(pid1, NULL, 0);

    return 0;
}
