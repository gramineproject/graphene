#define _XOPEN_SOURCE 700
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void child_handler(int sig) {
    /* should never be printed because child doesn't inherit this handler */
    printf("Handled SIGCHLD\n");
}

int main(int argc, const char** argv, const char** envp) {
    /* set signal handler for SIGCHLD signal */
    struct sigaction sa = {0};
    sa.sa_handler = child_handler;
    int ret = sigaction(SIGCHLD, &sa, NULL);
    if (ret < 0) {
        perror("sigaction error");
        return 1;
    }

    printf("Set up handler for SIGCHLD\n");
    fflush(stdout);

    /* SIGCHLD signal handler must *not* be inherited by execv'ed child */
    char* const new_argv[] = {"./fork_and_exec", NULL};
    execv(new_argv[0], new_argv);

    perror("execv failed");
    return 1;
}
