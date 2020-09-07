#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    int p[2];

    if (pipe2(p, O_NONBLOCK | O_CLOEXEC) < 0) {
        err(1, "pipe2");
    }

    ssize_t ret = write(p[1], "a", 1);
    if (ret < 0) {
        err(1, "write");
    } else if (ret != 1) {
        errx(1, "invalid return value from write: %zd\n", ret);
    }

    char c;
    ret = read(p[0], &c, 1);
    if (ret < 0) {
        err(1, "read");
    } else if (ret != 1) {
        errx(1, "invalid return value from read: %zd\n", ret);
    }

    ret = read(p[0], &c, 1);
    if (ret > 0) {
        errx(1, "read returned unexpected data: %zd\n", ret);
    } else if (ret == 0) {
        errx(1, "read returned 0 instead of EAGAIN\n");
    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        err(1, "unexpected read failure");
    }

    puts("TEST OK");
    return 0;
}
