#define _GNU_SOURCE
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
    if (argc != 1 && argc != 2) {
        errx(1, "invalid arguments count");
    }
    uint32_t expected_events = EPOLLIN;
    if (argc == 2 && !strcmp(argv[1], "EMULATE_GRAPHENE_BUG")) {
        /* More details: https://github.com/oscarlab/graphene/issues/1717 */
        expected_events |= EPOLLOUT;
    }

    int efd = epoll_create1(EPOLL_CLOEXEC);
    if (efd < 0) {
        err(1, "epoll_create1");
    }

    int p[2];
    if (pipe2(p, O_NONBLOCK) < 0) {
        err(1, "pipe2");
    }

    struct epoll_event event = {
        .events = EPOLLIN | EPOLLOUT | EPOLLPRI | EPOLLET,
        .data.fd = p[0],
    };
    if (epoll_ctl(efd, EPOLL_CTL_ADD, p[0], &event) < 0) {
        err(1, "EPOLL_CTL_ADD");
    }

    if (write(p[1], "", 1) != 1) {
        err(1, "write");
    }
    if (write(p[1], "", 1) != 1) {
        err(1, "write");
    }

    memset(&event, '\0', sizeof(event));
    if (epoll_wait(efd, &event, 1, -1) != 1) {
        err(1, "epoll_wait");
    }

    if (event.data.fd != p[0]) {
        errx(1, "epoll invalid data: %d", event.data.fd);
    }
    if (event.events != expected_events) {
        errx(1, "epoll invalid events: 0x%x", event.events);
    }

    char c;
    if (read(p[0], &c, 1) != 1) {
        err(1, "read");
    }

    memset(&event, '\0', sizeof(event));
    int ret = epoll_wait(efd, &event, 1, 10);

    if (ret < 0) {
        err(1, "epoll_wait");
    } else if (ret != 0) {
        errx(1, "EPOLLET reported 2 times: %d", ret);
    }

    puts("TEST OK");
    return 0;
}
