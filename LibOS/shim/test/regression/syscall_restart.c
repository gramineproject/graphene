#define _GNU_SOURCE
#include <err.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void child(int fd, int sig) {
    /* We need to wait till parent sleeps on `read`, unfortunately there is no way to check that in
     * Graphene. Hopefully 100ms is enough. Worst case scenario this test succeeds without actually
     * testing anything useful. */
    if (usleep(100 * 1000) < 0) {
        err(1, "usleep");
    }

    if (kill(getppid(), sig) < 0) {
        err(1, "kill");
    }

    /* Let parent notice the signal. */
    if (usleep(100 * 1000) < 0) {
        err(1, "usleep");
    }

    char c = 'A' + sig;
    if (write(fd, &c, 1) != 1) {
        err(1, "write");
    }
}

static void handler(int sig) {
    printf("Handling signal %d\n", sig);
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
        child(pfd[1], SIGCHLD);
        return 0;
    }

    char c = 0;
    if (read(pfd[0], &c, 1) != 1) {
        err(1, "read");
    }
    printf("Got: %c\n", c);

    int status = 0;
    if (waitpid(p, &status, 0) < 0) {
        err(1, "wait");
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        errx(1, "child died with: %d", status);
    }
    puts("TEST 1 OK");

    struct sigaction sa = {
        .sa_handler = handler,
        .sa_flags = SA_RESTART,
    };
    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        err(1, "sigaction");
    }

    p = fork();
    if (p < 0) {
        err(1, "fork");
    } else if (p == 0) {
        if (close(pfd[0]) < 0) {
            err(1, "close");
        }
        child(pfd[1], SIGTERM);
        return 0;
    }

    c = 0;
    if (read(pfd[0], &c, 1) != 1) {
        err(1, "read");
    }
    printf("Got: %c\n", c);

    if (waitpid(p, &status, 0) < 0) {
        err(1, "wait");
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        errx(1, "child died with: %d", status);
    }
    puts("TEST 2 OK");

    return 0;
}
