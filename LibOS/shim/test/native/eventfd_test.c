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

/* To support regression testing, positive value returned for error case.
 *
 */
int eventfd_using_poll() {
    int ret = 0;
    struct pollfd pollfds[MAX_EFDS];
    pthread_t pid = 0;
    uint64_t count = 0;
    int poll_ret = 0;
    int nread_events = 0;

    for (int cnt = 0; cnt < MAX_EFDS; cnt++) {
        efds[cnt] = eventfd(0, 0);

        if (efds[cnt] < 0) {
            perror("eventfd failed");
            return 1;
        }

        printf("efd = %d\n", efds[cnt]);

        pollfds[cnt].fd = efds[cnt];
        pollfds[cnt].events = POLLIN;
    }

    ret = pthread_create(&pid, NULL, write_eventfd_thread, efds);

    if (ret != 0) {
        perror("error in thread creation\n");
        return 1;
    } else
        printf("ret=%d, thread spawned fine. \n", ret);

    while (1) {
        poll_ret = poll(pollfds, MAX_EFDS, 5000);

        if (poll_ret == 0) {
            printf("Indicates timeout. Done processing. Exit. \n");
            break;
        }

        if (poll_ret < 0) {
            perror("error from poll");
            printf("error=%d, so exiting\n", errno);
            ret = 1;
            break;
        }

        for (int i = 0; i < MAX_EFDS; i++) {
            if (pollfds[i].revents & POLLIN) {
                pollfds[i].revents = 0;
                read(pollfds[i].fd, &count, sizeof(count));
                printf("fd set=%d\n", pollfds[i].fd);
                printf("parent-pid=%d, efd = %d, count: %lu, errno=%d\n", getpid(), pollfds[i].fd,
                        count, errno);
                nread_events++;
            }
        }

    }

    if (nread_events == MAX_EFDS) {
        printf("%s completed successfully\n", __func__);
    } else
        printf("%s: nread_events=%d, MAX_EFDS=%d\n",
                __func__, nread_events, MAX_EFDS);

    pthread_join(pid, NULL);

    return ret;
}

/* To support regression testing, positive value returned for error case.*/
int eventfd_using_various_flags() {

    uint64_t count = 0;
    int efd = 0;
    int eventfd_flags[] = { 0, EFD_NONBLOCK, EFD_CLOEXEC, EFD_NONBLOCK | EFD_CLOEXEC };

    for (int i = 0; i < sizeof(eventfd_flags) / sizeof(int); i++) {
        count = 5;
        printf("iteration #-%d, flags=%d\n", i, eventfd_flags[i]);

        efd = eventfd(0, eventfd_flags[i]);

        if (efd < 0) {
            perror("eventfd failed");
            return 1;
        }

        eventfd_write(efd, count);
        eventfd_write(efd, count);
        count = 0;
        eventfd_read(efd, &count);
        printf("efd = %d, count: %lu, errno=%d\n", efd, count, errno);
        count = 0;

        //Note: Calling another read, will block, if flags dont have EFD_NONBLOCK
        if (eventfd_flags[i] & EFD_NONBLOCK) {
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
