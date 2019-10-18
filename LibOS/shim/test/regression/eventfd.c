#include <errno.h>

#include <poll.h>
#include <pthread.h>

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_EFDS 3

int efds[MAX_EFDS] = { 0 };

void* write_eventfd_thread(void* arg) {
    uint64_t count = 10;

    int* efds = (int*) arg;

    if (!arg) {
        printf("arg is NULL\n");
        return NULL;
    }

    printf("%s:got here\n", __func__);

    for (int i = 0; i < MAX_EFDS; i++) {
        printf("%s: efd = %d\n", __func__, efds[i]);
    }

    for (int i = 0; i < MAX_EFDS; i++) {
        sleep(1);
        write(efds[i], &count, sizeof(count));
        count += 1;
    }

    return NULL;
}

/* This function used to test polling on a group of eventfd descriptors.
 * To support regression testing, positive value returned for error case. */
int eventfd_using_poll() {
    int ret = 0;
    struct pollfd pollfds[MAX_EFDS];
    pthread_t tid = 0;
    uint64_t count = 0;
    int poll_ret = 0;
    int nread_events = 0;

    for (int i = 0; i < MAX_EFDS; i++) {
        efds[i] = eventfd(0, 0);

        if (efds[i] < 0) {
            perror("eventfd failed");
            return 1;
        }

        printf("efd = %d\n", efds[i]);

        pollfds[i].fd = efds[i];
        pollfds[i].events = POLLIN;
    }

    ret = pthread_create(&tid, NULL, write_eventfd_thread, efds);

    if (ret != 0) {
        perror("error in thread creation\n");
        return 1;
    }

    while (1) {
        poll_ret = poll(pollfds, MAX_EFDS, 5000);

        if (poll_ret == 0) {
            printf("Poll timed out. Exiting.\n");
            break;
        }

        if (poll_ret < 0) {
            perror("error from poll");
            ret = 1;
            break;
        }

        for (int i = 0; i < MAX_EFDS; i++) {
            if (pollfds[i].revents & POLLIN) {
                pollfds[i].revents = 0;
                errno = 0;
                read(pollfds[i].fd, &count, sizeof(count));
                printf("fd set=%d\n", pollfds[i].fd);
                printf("efd = %d, count: %lu, errno=%d\n", pollfds[i].fd,
                        count, errno);
                nread_events++;
            }
        }
    }

    if (nread_events == MAX_EFDS) {
        printf("%s completed successfully\n", __func__);
    } else
        printf("%s: nread_events=%d, MAX_EFDS=%d\n", __func__, nread_events, MAX_EFDS);

    pthread_join(tid, NULL);
    return ret;
}

/* This function used to test various flags supported while creating eventfd descriptors.
 * Note: EFD_SEMAPHORE has not been tested.
 * To support regression testing, positive value returned for error case. */
int eventfd_using_various_flags() {
    uint64_t count = 0;
    int efd = 0;
    int eventfd_flags[] = { 0, EFD_NONBLOCK, EFD_CLOEXEC, EFD_NONBLOCK | EFD_CLOEXEC };

    for (int i = 0; i < sizeof(eventfd_flags) / sizeof(int); i++) {
        printf("iteration #-%d, flags=%d\n", i, eventfd_flags[i]);

        efd = eventfd(0, eventfd_flags[i]);

        if (efd < 0) {
            perror("eventfd failed");
            printf("eventfd error for iteration #-%d, flags-%d\n", i, eventfd_flags[i]);
            return 1;
        }

        count = 5;
        eventfd_write(efd, count);
        eventfd_write(efd, count);
        count = 0;
        errno = 0;
        eventfd_read(efd, &count);
        printf("efd = %d, count: %lu, errno=%d\n", efd, count, errno);

        //Note: Calling another read, will block, if flags dont have EFD_NONBLOCK
        if (eventfd_flags[i] & EFD_NONBLOCK) {
            count = 0;
            errno = 0;
            eventfd_read(efd, &count);
            printf("efd = %d, count: %lu, errno=%d\n", efd, count, errno);
        }

        close(efd);
    }

    printf("%s completed successfully\n", __func__);

    return 0;
}

int main(int argc, char* argv[]) {
    int ret = 0;

    ret = eventfd_using_poll();
    ret += eventfd_using_various_flags();

    return ret;
}
