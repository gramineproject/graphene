/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
    pid_t pid = vfork();
    if (pid < 0) {
        printf("failed on vfork (%s)\n", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        printf("[pid=%d|ppid=%d] Hello, Dad!\n", getpid(), getppid());
        _exit(0);
    }
    else {
        printf("[pid=%d|ppid=%d] Hello, Kid!\n", getpid(), getppid());
    }

    return 0;
}
