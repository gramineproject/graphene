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

#define PAYLOAD_SIZE    10

struct msgbuf {
    long    mtype;
    char    mtext[PAYLOAD_SIZE];
};

#define TEST_TIMES 1000
#define TEST_TYPES 2
#define DO_BENCH   1

enum { PARALLEL, SERIAL, IN_PROCESS } mode = PARALLEL;
int pipefds[4], key;

/* server always sends messages */
int server (void)
{
    struct timeval tv1, tv2;
    int msqid;
    struct msgbuf buf;
    size_t len;
    int i;

    if ((msqid = msgget(key, mode == SERIAL ? 0600|IPC_CREAT : 0)) < 0) {
        perror("msgget");
        exit(1);
    }

    gettimeofday(&tv1, NULL);

    for (i = 0 ; i < TEST_TIMES ; i++) {
        buf.mtype = (i % TEST_TYPES) + 1;
        if (msgsnd(msqid, &buf, PAYLOAD_SIZE, 0) < 0) {
            perror("msgsnd");
            exit(1);
        }

#ifndef DO_BENCH
        printf("Message: \"%s\" sent\n", buf.mtext);
#endif
    }

    gettimeofday(&tv2, NULL);

    if (mode == PARALLEL) {
        char byte = 0;

        close(pipefds[0]);
        write(pipefds[1], &byte, 1);

        close(pipefds[3]);
        read(pipefds[2], &byte, 1);
    }

    printf("time spent on %d msgsnd: %llu microsecond\n",
           TEST_TIMES,
           (tv2.tv_sec * 1000000ull + tv2.tv_usec) -
           (tv1.tv_sec * 1000000ull + tv1.tv_usec));

    if (mode != IN_PROCESS)
        exit(0);
}

/* client always sends messages */
int client (void)
{
    struct timeval tv1, tv2;
    int msqid;
    struct msgbuf buf;
    int i, ret;

    if (mode == PARALLEL) {
        char byte = 0;
        close(pipefds[1]);
        read(pipefds[0], &byte, 1);
    }

    if ((msqid = msgget(key, 0)) < 0) {
        perror("msgget");
        exit(1);
    }

    gettimeofday(&tv1, NULL);

    for (int i = 0 ; i < TEST_TIMES ; i++) {
        int type = (i % TEST_TYPES) + 1;
        if ((ret = msgrcv(msqid, &buf, PAYLOAD_SIZE, type, 0)) < 0) {
            perror("msgrcv");
            exit(1);
        }

#ifndef DO_BENCH
        buf.mtext[ret] = 0;
        printf("Client received: \"%s\"\n", buf.mtext);
#endif
    }

    gettimeofday(&tv2, NULL);

    if (mode == PARALLEL) {
        char byte = 0;
        close(pipefds[2]);
        write(pipefds[3], &byte, 1);
    }

    printf("time spent on %d msgrcv: %llu microsecond\n",
           TEST_TIMES,
           (tv2.tv_sec * 1000000ull + tv2.tv_usec) -
           (tv1.tv_sec * 1000000ull + tv1.tv_usec));

    if (mode != IN_PROCESS)
        exit(0);
}

int main (int argc, char ** argv)
{
    int msqid;

    key = rand();

#ifndef DO_BENCH
    printf("Msg queue key: 0x%8x\n", key);
#endif

    /* server run first and client run later */
    if (argc == 2 && strcmp(argv[1], "serial") == 0) {
        mode = SERIAL;
        if (fork() == 0)
            server();
        wait(NULL);
        if (fork() == 0)
            client();
        wait(NULL);
        msgctl(msqid, IPC_RMID, NULL);
        return 0;
    }

    if ((msqid = msgget(key, 0600|IPC_CREAT)) < 0) {
        perror("msgget");
        exit(1);
    }

    /* server run first and client run later (in the same process) */
    if (argc == 2 && strcmp(argv[1], "in-process") == 0) {
        mode = IN_PROCESS;
        server();
        client();
        msgctl(msqid, IPC_RMID, NULL);
        return 0;
    }

    pipe(&pipefds[0]);
    pipe(&pipefds[2]);

    /* server to be the parent and client to be the child */
    if (argc == 1) {
        if (fork() == 0)
            client();
        else
            server();
    }

    /* client to be the parent and server to be the child */
    if (argc == 2 && strcmp(argv[1], "reverse") == 0) {
        if (fork() == 0)
            server();
        else
            client();
    }

    /* both client and server are children */
    if (argc == 2 && strcmp(argv[1], "children") == 0) {
        if (fork() == 0)
            server();
        if (fork() == 0)
            client();
        wait(NULL);
        wait(NULL);
    }

    msgctl(msqid, IPC_RMID, NULL);
    return 0;
}
