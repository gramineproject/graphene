/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation */

/*
 * Test to set/get cpu affinity by parent process on behalf of its child threads.
 */

#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Set large busy loops so that we can verify affinity with htop manually*/
static void* dowork(void* args) {
    __asm__ volatile (
                      "movq $10000000000, %%rax\n"
                      "loop:\n"
                      "dec %%rax\n"
                      "cmp $0, %%rax\n"
                      "jne loop\n"
                      : /*no outs*/ : /*no ins*/ : "%rax", "%cc");
    return NULL;
}

int main(int argc, const char** argv) {

    int ret;
    long numprocs = sysconf(_SC_NPROCESSORS_ONLN);
    if (numprocs < 0) {
        err(EXIT_FAILURE, "Failed to retrieve the number of logical processors!");
    }

    /* Affinitize threads to alternate logical processors to do a quick check from htop manually */
    numprocs = (numprocs >= 2)? numprocs/2 : 1;

    pthread_t threads[numprocs];
    cpu_set_t cpus, get_cpus;

    /* Validate parent set/get affinity for child */
    for (long i = 0; i < numprocs; i++) {
        CPU_ZERO(&cpus);
        CPU_ZERO(&get_cpus);
        CPU_SET(i*2, &cpus);

        ret = pthread_create(&threads[i], NULL, dowork, NULL);
        if (ret != 0) {
            err(EXIT_FAILURE, "pthread_create failed!");
        }

        ret = pthread_setaffinity_np(threads[i], sizeof(cpus), &cpus);
        if (ret != 0) {
            err(EXIT_FAILURE, "pthread_setaffinity_np failed for child!");
        }

        ret = pthread_getaffinity_np(threads[i], sizeof(get_cpus), &get_cpus);
        if (ret != 0) {
            err(EXIT_FAILURE, "pthread_getaffinity_np failed for child!");
        }

        if (!CPU_EQUAL_S(sizeof(cpus), &cpus, &get_cpus)) {
            errx(EXIT_FAILURE, "get cpuset is not equal to set cpuset on proc: %ld", i);
        }
    }

    for (int i = 0; i < numprocs; i++) {
        ret = pthread_join(threads[i], NULL);
        if (ret != 0) {
            err(EXIT_FAILURE, "pthread_join failed!");
        }
    }

    /* Validate parent set/get affinity for itself */
    CPU_ZERO(&cpus);
    CPU_SET(0, &cpus);
    ret = pthread_setaffinity_np(pthread_self(), sizeof(cpus), &cpus);
    if (ret != 0) {
        err(EXIT_FAILURE, "pthread_setaffinity_np failed for parent!");
    }

    CPU_ZERO(&get_cpus);
    ret = pthread_getaffinity_np(pthread_self(), sizeof(get_cpus), &get_cpus);
    if (ret != 0) {
        err(EXIT_FAILURE, "pthread_getaffinity_np failed for parent!");
    }

    if (!CPU_EQUAL_S(sizeof(cpus), &cpus, &get_cpus)) {
        errx(EXIT_FAILURE, "get cpuset is not equal to set cpuset on proc 0");
    }

    /* Negative test case with empty cpumask*/
    CPU_ZERO(&cpus);
    ret = pthread_setaffinity_np(pthread_self(), sizeof(cpus), &cpus);
    if (ret != EINVAL) {
        err(EXIT_FAILURE, "pthread_setaffinity_np with empty cpumask did not return EINVAL!");
    }

    printf("TEST OK\n");
    return 0;
}
