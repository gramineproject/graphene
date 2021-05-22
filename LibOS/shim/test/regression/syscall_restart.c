#define _GNU_SOURCE
#include <err.h>
#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void child(int fd) {
    /* We need to wait till parent sleeps on `read`, unfortunately there is no way to check that in
     * Graphene. Hopyfully 100ms is enough. */
    if (usleep(100 * 1000) < 0) {
        err(1, "usleep");
    }

    if (kill(getppid(), SIGCHLD) < 0) {
        err(1, "kill");
    }

    /* Let parent notice the signal. */
    if (usleep(100 * 1000) < 0) {
        err(1, "usleep");
    }

    char c = 'a';
    if (write(fd, &c, 1) != 1) {
        err(1, "write");
    }
}

int main(int argc, char** argv) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    int pfd[2];
    if (pipe(pfd) < 0) {
        err(1, "pipe");
    }

    pid_t p = fork();
    if (p < 0) {
        err(1, "fork");
    } else if (p == 0) {
        if (close(pfd[0]) < 0) {
            err(1, "close");
        }
        child(pfd[1]);
        return 0;
    }

    char c = 0;
    if (read(pfd[0], &c, 1) != 1) {
        err(1, "read");
    }

    int status = 0;
    if (waitpid(p, &status, 0) < 0) {
        err(1, "wait");
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        errx(1, "child died with: %d", status);
    }

    puts("TEST OK");
    return 0;
}
