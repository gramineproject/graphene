#define _XOPEN_SOURCE 700
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/signal.h>
#include <sys/wait.h>
#include <unistd.h>

static int count = 0;

static void handler(int signum) {
    printf("Got signal %d\n", signum);
    fflush(stdout);
    count++;
}

int main() {

    struct sigaction action;
    action.sa_handler = handler;
    action.sa_flags = SA_RESETHAND; // one shot

    int ret = sigaction(SIGCHLD, &action, NULL);
    if (ret < 0) {
        fprintf(stderr, "sigaction failed\n");
        return 1;
    }

    int pid = fork();
    if (pid < 0) {
        fprintf(stderr, "fork failed\n");
        return 1;
    }

    if (pid == 0) {
        /* child signals parent -- only 1 must go through */
        kill(getppid(), SIGCHLD);
        kill(getppid(), SIGCHLD);
        exit(0);
    }

    wait(NULL);

    printf("Handler was invoked %d time(s).\n", count);

    if (count != 1)
        return 1;

    return 0;
}
