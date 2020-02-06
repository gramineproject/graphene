#define _XOPEN_SOURCE 700
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

int kill_parent = 0;

int main(int argc, char** argv) {
    if (argc == 2 && !strcmp("parent", argv[1]))
        kill_parent = 1;

    int parent_pid = getpid();

    pid_t pid = fork();
    if (pid < 0) {
        printf("failed on fork (%s)\n", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        struct timespec rem;
        rem.tv_sec  = kill_parent ? 1 : 60;
        rem.tv_nsec = 0;

        printf("[pid=%d|ppid=%d] Going to sleep...\n", getpid(), getppid());

        nanosleep(&rem, 0);

        if (kill_parent)
            kill(parent_pid, SIGKILL);

        printf("[pid=%d|ppid=%d] Hello, Dad!\n", getpid(), getppid());
    } else {
        struct timespec rem;
        rem.tv_sec  = kill_parent ? 60 : 1;
        rem.tv_nsec = 0;

        printf("[pid=%d|ppid=%d] Going to sleep...\n", getpid(), getppid());

        nanosleep(&rem, 0);

        if (!kill_parent)
            kill(pid, SIGKILL);

        printf("[pid=%d|ppid=%d] Hello, Kid!\n", getpid(), getppid());
    }
    return 0;
}
