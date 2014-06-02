/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <errno.h>

#define TEST_TIMES    4

int main (int argc, const char * argv)
{
    int ret = 0;
    int fds[TEST_TIMES][2];

    int efd = epoll_create(TEST_TIMES);
    if (!efd < 0) {
        perror("epoll_create");
        exit(1);
    }

    struct epoll_event event;

    for (int i = 0 ; i < TEST_TIMES ; i++) {
        ret = pipe(fds[i]);
        if (ret < 0) {
            perror("pipe");
            exit(1);
        }

        event.events = EPOLLIN;
        event.data.fd = fds[i][0];

        ret = epoll_ctl(efd, EPOLL_CTL_ADD, fds[i][0], &event);
        if (ret < 0) {
            perror("epoll_ctl add");
            exit(1);
        }
    }

    ret = fork();
    if (ret < 0) {
        perror("fork");
        exit(1);
    }

    if (!ret) {
        for (int i = 0 ; i < TEST_TIMES ; i++) {
            close(fds[i][0]);
            char c = 0;
            write(fds[i][1], &c, 1);
            close(fds[i][1]);
        }

        exit(0);
    }

    for (int i = 0 ; i < TEST_TIMES ; i++)
        close(fds[i][1]);

    for (int i = 0 ; i < TEST_TIMES ; i++) {
        ret = epoll_wait(efd, &event, 1, -1);
        if (ret < 0) {
            perror("epoll_wait");
            exit(1);
        }

        if (!ret)
            break;

        if (event.events & EPOLLIN) {
            char c;
            read(event.data.fd, &c, 1);
        }

        printf("fd %d polled:", event.data.fd);
        if (event.events & EPOLLIN)
            printf(" EPOLLIN");
        if (event.events & EPOLLERR)
            printf(" EPOLLERR");
        if (event.events & EPOLLHUP)
            printf(" EPOLLHUP");
        if (event.events & EPOLLRDHUP)
            printf(" EPOLLRDHUP");
        printf("\n");
    }

    return 0;
}
