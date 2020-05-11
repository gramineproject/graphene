#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <signal.h>
#include <sys/signal.h>
#include <string.h>
#include <errno.h>

static int sigpipe_ctr = 0;

static void sigpipe_handler(int signum, siginfo_t *si, void *uc)
{
    printf("Got signal %d\n", signum);
    if (signum == SIGPIPE)
        sigpipe_ctr++;
}

int main(void)
{
    int fds[2];
    int n;
    const struct sigaction act = {
        .sa_sigaction = sigpipe_handler,
    };
    struct sigaction oldact;

    n = sigaction(SIGPIPE, &act, &oldact);
    if (n < 0) {
        fprintf(stderr, "sigaction failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    n = pipe(fds);
    if (n < 0) {
        fprintf(stderr, "Could not create pipe: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* close read end */
    close(fds[0]);

    n = write(fds[1], "!", 1);
    /* we expect a failure */
    if (n < 0) {
        fprintf(stderr, "Could not write to pipe: %s\n", strerror(errno));
    }

    printf("Got %d SIGPIPE signal(s)\n", sigpipe_ctr);
    fflush(stderr);
    fflush(stdout);

    n = sigaction(SIGPIPE, &oldact, NULL);
    if (n < 0) {
        fprintf(stderr, "sigaction failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* this write has to terminate us */
    n = write(fds[1], "!", 1);
    /* we should never get here */

    exit(EXIT_SUCCESS);
}
