/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <shim_unistd.h>

#define PAYLOAD_SIZE 4

struct msgbuf {
    long    mtype;
    char    mtext[PAYLOAD_SIZE];
};

#define TEST_TIMES 1000
#define DO_BENCH   1

int msqid;

/* server always sends messages */
int server (void)
{
    struct timeval tv1, tv2;
    struct msgbuf buf;
    int i;

    buf.mtype = 1;

    gettimeofday(&tv1, NULL);

    for (i = 0 ; i < TEST_TIMES ; i++) {
        if (msgsnd(msqid, &buf, PAYLOAD_SIZE, 0) < 0) {
            perror("msgsnd");
            exit(1);
        }

#ifndef DO_BENCH
        printf("Message: \"%s\" sent\n", buf.mtext);
#endif
    }

    msgpersist(msqid, MSGPERSIST_STORE);

    gettimeofday(&tv2, NULL);

    printf("time spent on %d msgsnd: %llu microsecond\n",
           TEST_TIMES,
           (tv2.tv_sec * 1000000ull + tv2.tv_usec) -
           (tv1.tv_sec * 1000000ull + tv1.tv_usec));
}

/* client always sends messages */
int client (void)
{
    struct timeval tv1, tv2;
    struct msgbuf buf;
    int i, ret;

    gettimeofday(&tv1, NULL);

    msgpersist(msqid, MSGPERSIST_LOAD);

    for (int i = 0 ; i < TEST_TIMES ; i++) {
        if ((ret = msgrcv(msqid, &buf, PAYLOAD_SIZE, 1, 0)) < 0) {
            perror("msgrcv");
            exit(1);
        }

#ifndef DO_BENCH
        buf.mtext[ret] = 0;
        printf("Client received: \"%s\"\n", buf.mtext);
#endif
    }

    gettimeofday(&tv2, NULL);

    printf("time spent on %d msgrcv: %llu microsecond\n",
           TEST_TIMES,
           (tv2.tv_sec * 1000000ull + tv2.tv_usec) -
           (tv1.tv_sec * 1000000ull + tv1.tv_usec));

    msgctl(msqid, IPC_RMID, NULL);
}

int main (int argc, char ** argv)
{
    if ((msqid = msgget(IPC_PRIVATE, 0600|IPC_CREAT)) < 0) {
        perror("msgget");
        exit(1);
    }

    server();
    client();

    return 0;
}
