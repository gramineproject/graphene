#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define TEST_TIMES 1000
#define DO_BENCH   1

enum { PARALLEL, SERIAL, IN_PROCESS } mode = PARALLEL;
int pipefds[2], key;

/* server always sends messages */
void server(void) {
    struct timeval tv1, tv2;
    int semid;
    struct sembuf buf;

    if ((semid = semget(key, 2, mode == SERIAL ? 0600 | IPC_CREAT : 0)) < 0) {
        perror("semget");
        exit(1);
    }

    gettimeofday(&tv1, NULL);

    for (int i = 0; i < TEST_TIMES; i++) {
        buf.sem_num = 0;
        buf.sem_op  = 1;
        buf.sem_flg = 0;
        if (semop(semid, &buf, 1) < 0) {
            perror("semop");
            exit(1);
        }

#ifndef DO_BENCH
        printf("Semaphore %d signaled\n", i);
#endif
    }

    gettimeofday(&tv2, NULL);

    printf("time spent on %d semop (signal): %llu microsecond\n", TEST_TIMES,
           (tv2.tv_sec * 1000000ull + tv2.tv_usec) - (tv1.tv_sec * 1000000ull + tv1.tv_usec));

    if (mode == PARALLEL) {
        close(pipefds[0]);
        char byte = 0;
        if (write(pipefds[1], &byte, 1) != 1) {
            perror("write error");
            exit(1);
        }

        buf.sem_num = 1;
        buf.sem_op  = -1;
        buf.sem_flg = 0;
        if (semop(semid, &buf, 1) < 0) {
            perror("semop");
            exit(1);
        }

        semctl(semid, 0, IPC_RMID);
    }

    if (mode != IN_PROCESS)
        exit(0);
}

/* client always sends messages */
void client(void) {
    struct timeval tv1, tv2;
    int semid;
    struct sembuf buf;

    if (mode == PARALLEL) {
        close(pipefds[1]);
        char byte = 0;
        if (read(pipefds[0], &byte, 1) != 1) {
            perror("read error");
            exit(1);
        }
    }

    if ((semid = semget(key, 0, 0)) < 0) {
        perror("semget");
        exit(1);
    }

    gettimeofday(&tv1, NULL);

    for (int i = 0; i < TEST_TIMES; i++) {
        buf.sem_num = 0;
        buf.sem_op  = -1;
        buf.sem_flg = 0;
        if (semop(semid, &buf, 1) < 0) {
            perror("semop");
            exit(1);
        }

#ifndef DO_BENCH
        printf("Semaphore %d wakened\n", i);
#endif
    }

    gettimeofday(&tv2, NULL);

    if (mode == PARALLEL) {
        buf.sem_num = 1;
        buf.sem_op  = 1;
        buf.sem_flg = 0;
        if (semop(semid, &buf, 1) < 0) {
            perror("semop");
            exit(1);
        }
    } else {
        semctl(semid, 0, IPC_RMID);
    }

    printf("time spent on %d semop (wait): %llu microsecond\n", TEST_TIMES,
           (tv2.tv_sec * 1000000ull + tv2.tv_usec) - (tv1.tv_sec * 1000000ull + tv1.tv_usec));

    if (mode != IN_PROCESS)
        exit(0);
}

int main(int argc, char** argv) {
    int semid;

    key = rand();

#ifndef DO_BENCH
    printf("Semaphore key: 0x%8x\n", key);
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
    }

    if ((semid = semget(key, 2, 0600 | IPC_CREAT)) < 0) {
        perror("semget");
        exit(1);
    }

    /* server run first and client run later (in the same process) */
    if (argc == 2 && strcmp(argv[1], "in-process") == 0) {
        mode = IN_PROCESS;
        server();
        client();
        semctl(semid, 0, IPC_RMID);
        return 0;
    }

    if (pipe(pipefds) < 0) {
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

    semctl(semid, 0, IPC_RMID);

    return 0;
}
