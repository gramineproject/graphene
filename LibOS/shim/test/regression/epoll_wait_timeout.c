#define _XOPEN_SOURCE 700
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* On success, a file descriptor for the new socket is returned.
 * On error, -1 is returned. */
static int create_and_bind(char* port) {
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, sfd;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family   = AF_UNSPEC;   /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */
    hints.ai_flags    = AI_PASSIVE;  /* All interfaces */

    s = getaddrinfo(NULL, port, &hints, &result);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1)
            continue;

        s = bind(sfd, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            /* We managed to bind successfully! */
            break;
        }

        close(sfd);
    }

    if (rp == NULL) {
        fprintf(stderr, "Could not bind\n");
        return -1;
    }

    freeaddrinfo(result);
    return sfd;
}

/* On success, 0 is returned. On error, -1 is returned. */
static int make_socket_non_blocking(int sfd) {
    int flags, s;

    flags = fcntl(sfd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl");
        return -1;
    }

    flags |= O_NONBLOCK;
    s = fcntl(sfd, F_SETFL, flags);
    if (s == -1) {
        perror("fcntl");
        return -1;
    }

    return 0;
}

#define MAXEVENTS 64

int main(int argc, char* argv[]) {
    int sfd, s, n;
    int efd;
    struct epoll_event event;
    struct epoll_event* events;

    if (argc != 2) {
        perror("please specify port");
        return 1;
    }

    sfd = create_and_bind(argv[1]);
    if (sfd == -1)
        return 1;

    s = make_socket_non_blocking(sfd);
    if (s == -1)
        return 1;

    s = listen(sfd, SOMAXCONN);
    if (s == -1) {
        perror("listen");
        return 1;
    }

    efd = epoll_create1(0);
    if (efd == -1) {
        perror("epoll_create");
        return 1;
    }

    event.data.fd = sfd;
    event.events  = EPOLLIN | EPOLLET;
    s             = epoll_ctl(efd, EPOLL_CTL_ADD, sfd, &event);
    if (s == -1) {
        perror("epoll_ctl");
        return 1;
    }

    events = calloc(MAXEVENTS, sizeof event);

    /* epoll_wait with 1 second timeout */
    n = epoll_wait(efd, events, MAXEVENTS, 1000);
    if (n == -1) {
        perror("epoll_wait");
        return 1;
    }

    printf("epoll_wait test passed\n");
    free(events);
    close(sfd);
    return 0;
}
