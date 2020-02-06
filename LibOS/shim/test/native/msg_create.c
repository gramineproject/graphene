/* Test to create 100 message queues and query them from another process*/

#define _GNU_SOURCE
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

enum { PARALLEL, SERIAL, IN_PROCESS } mode = PARALLEL;
int pipefds[4];
int keys[TEST_TIMES];

/* server always creates queues */
void server(void) {
    struct timeval tv1, tv2;
    int i;

    gettimeofday(&tv1, NULL);

    for (i = 0; i < TEST_TIMES; i++) {
        create_q(keys[i]);
    }

    gettimeofday(&tv2, NULL);

    if (mode == PARALLEL) {
        close(pipefds[0]);
        char byte;
        if (write(pipefds[1], &byte, 1) != 1) {
            perror("write error");
            exit(1);
        }
    }

    if (mode == PARALLEL) {
        close(pipefds[3]);
        char byte;
        if (read(pipefds[2], &byte, 1) != 1) {
            perror("read error");
            exit(1);
        }
    }

    printf("time spent on %d creation: %llu microsecond\n", TEST_TIMES,
           (tv2.tv_sec * 1000000ULL + tv2.tv_usec) - (tv1.tv_sec * 1000000ULL + tv1.tv_usec));

    if (mode != IN_PROCESS)
        exit(0);
}

/* client always connects queues */
void client(void) {
    struct timeval tv1, tv2;
    int i;
    int ids[TEST_TIMES];

    if (mode == PARALLEL) {
        close(pipefds[1]);
        char byte;
        if (read(pipefds[0], &byte, 1) != 1) {
            perror("read error");
            exit(1);
        }
    }

    gettimeofday(&tv1, NULL);

    for (i = 0; i < TEST_TIMES; i++) {
        ids[i] = connect_q(keys[i]);
    }

    gettimeofday(&tv2, NULL);

    for (i = 0; i < TEST_TIMES; i++) {
        msgctl(ids[i], IPC_RMID, NULL);
    }

    if (mode == PARALLEL) {
        close(pipefds[2]);
        char byte;
        if (write(pipefds[3], &byte, 1) != 1) {
            perror("write error");
            exit(1);
        }
    }

    printf("time spent on %d connection: %llu microsecond\n", TEST_TIMES,
           (tv2.tv_sec * 1000000ULL + tv2.tv_usec) - (tv1.tv_sec * 1000000ULL + tv1.tv_usec));

    if (mode != IN_PROCESS)
        exit(0);
}

int main(int argc, char** argv) {
    int i;

    for (i = 0; i < TEST_TIMES; i++) {
        keys[i] = rand();
    }

    if (pipe(pipefds) < 0 || pipe(pipefds + 2) < 0) {
        perror("pipe error");
        return 1;
    }
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

    /* server run first and client run later */
    if (argc == 2 && strcmp(argv[1], "serial") == 0) {
        mode = SERIAL;
        if (fork() == 0)
            server();
        wait(NULL);
        if (fork() == 0)
            client();
        wait(NULL);
    }

    /* server run first and client run later (in the same process) */
    if (argc == 2 && strcmp(argv[1], "in-process") == 0) {
        mode = IN_PROCESS;
        server();
        client();
    }

    return 0;
}
