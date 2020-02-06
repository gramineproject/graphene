/* Test to create 100 message queues and query them from another process*/

#define _XOPEN_SOURCE 700
#include <shim_unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

struct msg_buf {
    long mtype;
    char msgtext[512];
};

#define TEST_TIMES 1000
#define DO_BENCH   1

int create_q(int key) {
    int r = msgget(key, IPC_CREAT | 0600);

#ifndef DO_BENCH
    printf("The identifier used is %d\n", r);
#endif

    if (r < 0) {
        perror("msgget\n");
        exit(-1);
    }
#ifndef DO_BENCH
    else
        printf("Created a message queue\n");
#endif

    return r;
}

int connect_q(int key) {
    int r = msgget(key, 0);

#ifndef DO_BENCH
    printf("The identifier used is %d\n", r);
#endif

    if (r < 0) {
        perror("msgget");
        exit(-1);
    }
#ifndef DO_BENCH
    else
        printf("Connected the message queue\n");
#endif

    return r;
}

int keys[TEST_TIMES];
int ids[TEST_TIMES];

/* server always creates queues */
void server(void) {
    struct timeval tv1, tv2;
    int i;

    gettimeofday(&tv1, NULL);

    for (i = 0; i < TEST_TIMES; i++) {
        ids[i] = create_q(keys[i]);
    }

    for (i = 0; i < TEST_TIMES; i++) {
        msgpersist(ids[i], MSGPERSIST_STORE);
    }

    gettimeofday(&tv2, NULL);

    printf("time spent on %d creation: %llu microsecond\n", TEST_TIMES,
           (tv2.tv_sec * 1000000ULL + tv2.tv_usec) - (tv1.tv_sec * 1000000ULL + tv1.tv_usec));
}

/* client always connects queues */
void client(void) {
    struct timeval tv1, tv2;
    int i;

    gettimeofday(&tv1, NULL);

    for (i = 0; i < TEST_TIMES; i++) {
        msgpersist(ids[i], MSGPERSIST_LOAD);
    }

    gettimeofday(&tv2, NULL);

    printf("time spent on %d connection: %llu microsecond\n", TEST_TIMES,
           (tv2.tv_sec * 1000000ULL + tv2.tv_usec) - (tv1.tv_sec * 1000000ULL + tv1.tv_usec));

    for (i = 0; i < TEST_TIMES; i++) {
        msgctl(ids[i], IPC_RMID, NULL);
    }
}

int main(int argc, char** argv) {
    for (int i = 0; i < TEST_TIMES; i++) {
        keys[i] = rand();
    }

    server();
    client();

    return 0;
}
