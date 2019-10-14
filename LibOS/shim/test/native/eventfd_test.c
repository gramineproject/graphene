#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>

#include <pthread.h>
#include <stdarg.h>
#include <string.h>

#define MAX_EFDS 3

typedef struct _eventfd_info {
    int efd;
    int flags;
} eventfd_info;

int efds[MAX_EFDS] = { 0 };

void* write_eventfd_thread(void* arg) {
    uint64_t count = 10;

    int* efds = (int*) arg;
    int i = 0;

    if (!arg) {
        printf("arg is NULL\n");
        return NULL;
    }

    printf("%s:got here\n", __func__);

    for (i = 0; i < MAX_EFDS; i++) {
        printf("%s: efd = %d\n", __func__, efds[i]);
    }

    for (i = 0; i < MAX_EFDS; i++) {
        sleep(2);
        write(efds[i], &count, sizeof(count));
        count += 1;
    }

    return NULL;
}

int eventfd_using_poll() {
    int ret = 0;
    struct pollfd pollfds[MAX_EFDS];
    pthread_t pid = 0;
    uint64_t count = 0;

    for (int cnt = 0; cnt < MAX_EFDS; cnt++) {
        efds[cnt] = eventfd(0, 0);

        if (efds[cnt] == -1) {
            printf("error with eventfd init\n");
            return -1;
        }

        printf("efd = %d\n", efds[cnt]);

        pollfds[cnt].fd = efds[cnt];
        pollfds[cnt].events = POLLIN;
    }

    ret = pthread_create(&pid, NULL, write_eventfd_thread, efds);

    if (ret != 0) {
        perror("error in thread creation\n");
        return -1;
    } else
        printf("ret=%d, thread spawned fine. \n", ret);

    while (1) {
        ret = poll(pollfds, MAX_EFDS, 5000);

        if (ret == 0) {
            printf("based on the timeouts, expect to have processed all, so exiting\n");
            break;
        }

        if (ret < 0) {
            perror("error from poll");
            printf("error=%d, so exiting\n", errno);
            break;
        }

        for (int i = 0; i < MAX_EFDS; i++) {
            if (pollfds[i].revents & POLLIN) {
                pollfds[i].revents = 0;
                read(pollfds[i].fd, &count, sizeof(count));
                printf("fd set=%d\n", pollfds[i].fd);
                printf("parent-pid=%d, efd = %d, count: %lu, errno=%d\n", getpid(), pollfds[i].fd,
                        count, errno);
            }
        }

    }

    pthread_join(pid, NULL);

    return ret;
}

int eventfd_using_various_flags() {

    uint64_t count = 0;

    eventfd_info eventfd_it[] = { { 0, 0 }, { 0, EFD_NONBLOCK }, { 0, EFD_CLOEXEC }, { 0,
            EFD_NONBLOCK | EFD_CLOEXEC }, };

    for (int i = 0; i < sizeof(eventfd_it) / sizeof(eventfd_info); i++) {
        count = 5;
        printf("iteration #-%d, flags=%d\n", i, eventfd_it[i].flags);

        eventfd_it[i].efd = eventfd(0, eventfd_it[i].flags);

        eventfd_write(eventfd_it[i].efd, count);
        eventfd_write(eventfd_it[i].efd, count);
        count = 0;
        eventfd_read(eventfd_it[i].efd, &count);
        printf("efd = %d, count: %lu, errno=%d\n", eventfd_it[i].efd, count, errno);
        count = 0;

        //Note: Calling another read, will block, if flags dont have EFD_NONBLOCK
        if (eventfd_it[i].flags & EFD_NONBLOCK) {
            eventfd_read(eventfd_it[i].efd, &count);
            printf("efd = %d, count: %lu, errno=%d\n", eventfd_it[i].efd, count, errno);
        }

        close(eventfd_it[i].efd);
    }

    return 0;
}

int main(int argc, char* argv[]) {

    eventfd_using_poll();
    eventfd_using_various_flags();

    return 0;
}
