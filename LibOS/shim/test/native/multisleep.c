/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <sched.h>
#include <stdio.h>

#define SLEEP_TIME      10
#define FIBER_STACK     1024 * 64

int proc;

int thread_function (void * arg)
{
    int thread = (int) ((unsigned long) arg);
    printf("in process %d thread %d\n", proc, thread);
    for (int i = 0 ; i < SLEEP_TIME ; i++) {
        printf("in process %d thread %d: %d\n", proc, thread, i);
        sleep(1);
    }
    return 0;
}

int main(int argc, char ** argv)
{
    int nprocs = 1, nthreads = 1;
    int thread;

    setvbuf(stdout, NULL, _IONBF, 0);

    for (int i = 1 ; i < argc ; i++) {
        if (!strcmp(argv[i], "-n") && i + 1 < argc) {
            nprocs = atoi(argv[i + 1]);
            i++;
            continue;
        }

        if (!strcmp(argv[i], "-t") && i + 1 < argc) {
            nthreads = atoi(argv[i + 1]);
            i++;
            continue;
        }
    }

    for (proc = nprocs ; proc > 1 ; proc--) {
        int ret = fork();

        if (ret < 0) {
            perror("fork");
            _exit(1);
        }

        if (!ret)
            break;
    }

    for (thread = 1 ; thread < nthreads ; thread++) {
        void * stack = malloc(FIBER_STACK);
        if (!stack) {
            perror("malloc: could not allocate stack");
            _exit(1);
        }

        clone(&thread_function, (void *) stack + FIBER_STACK,
              CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_VM,
              (void *) ((unsigned long) thread + 1));
    }

    for (int i = 0 ; i < SLEEP_TIME ; i++) {
        printf("in process %d thread 1: %d\n", proc, i);
        sleep(1);
    }
    return 0;
}
