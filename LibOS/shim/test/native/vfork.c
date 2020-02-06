#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

int main() {
    pid_t pid = vfork();
    if (pid < 0) {
        printf("failed on vfork (%s)\n", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        printf("[pid=%d|ppid=%d] Hello, Dad!\n", getpid(), getppid());
        _exit(0);
    } else {
        printf("[pid=%d|ppid=%d] Hello, Kid!\n", getpid(), getppid());
    }

    return 0;
}
