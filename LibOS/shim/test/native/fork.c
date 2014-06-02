/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>

int main (int argc, const char ** argv)
{
    pid_t pid1 = fork();

    if (pid1 < 0) {
        printf("failed on fork (%s)\n", strerror(errno));
        return -1;
    }

    if (pid1 == 0) {
        pid_t pid2 = fork();

        if (pid2 < 0) {
            printf("failed on fork (%s)\n", strerror(errno));
            return -1;
        }

        if (pid2 == 0) {
            printf("[pid=%d|ppid=%d] Hello, Grandpa!\n", getpid(), getppid());
            return 0;
        }

        waitpid(-1, NULL, 0);
        printf("[pid=%d|ppid=%d] Hello, Dad!\n", getpid(), getppid());
        return 0;
    }

    waitpid(-1, NULL, 0);

    printf("[pid=%d|ppid=%d] Hello, Kid!\n", getpid(), getppid());
    return 0;
}
