#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, const char** argv) {
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
