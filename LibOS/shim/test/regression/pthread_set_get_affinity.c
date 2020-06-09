/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation */

/*
 * pthread_set_get_affinity.c
 *
 * Test to set/get cpu affinity by parent process on behalf of its child threads.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <math.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>

pid_t gettid(void);

pid_t gettid(void) {
    pid_t tid = (pid_t)syscall(SYS_gettid);
    return tid;
}

void* dowork(void* args);

void* dowork(void* args) {
    unsigned long int i;
    double x=945346346464.3453453453,y=7899.345345345,z=2343523523.242342342;
    for(i=0;i<100000000; i++)
        y = sqrt(x) * pow(x, y) * sin(z);
    return 0;
}

int main() {

    int ret;
    int numberOfProcessors = sysconf(_SC_NPROCESSORS_ONLN);
    printf("Number of processors: %d\n", numberOfProcessors);

    pthread_t threads[numberOfProcessors/2];

    pthread_attr_t attr;
    cpu_set_t cpus, get_cpus,temp;
    pthread_attr_init(&attr);

    for (int i = 0; i < numberOfProcessors/2; i++) {
        CPU_ZERO(&cpus);
        CPU_ZERO(&get_cpus);
        CPU_SET(i*2, &cpus);
        
        ret = pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpus);
        if (ret != 0) {
            printf("pthread_attr_setaffinity_np failed errno=%d\n", errno);
           return 1;
        }

        ret = pthread_attr_getaffinity_np(&attr, sizeof(cpu_set_t), &get_cpus);
        if (ret != 0) {
            printf("pthread_attr_getaffinity_np failed errno=%d\n", errno);
            return 1;
        }

        if (!CPU_EQUAL_S(sizeof(cpus), &cpus, &get_cpus)) {
            printf(" The get cpuset is not equal to set cpuset on proc: %d\n", i);
            return 1;
        }

        pthread_create(&threads[i], &attr, dowork, NULL);
    }
    
    for (int i = 0; i < numberOfProcessors/2; i++) {
        pthread_join(threads[i], NULL);
    }

    /* Negative test case */
    threads[0] = pthread_self();
    CPU_ZERO(&temp);
    ret = pthread_setaffinity_np(threads[0], sizeof(cpu_set_t), &temp);
    if (ret == 0) {
        printf("pthread_setaffinity_np with empty cpumask returned 0\n");
        return 1;
    }

    printf("TEST OK: test completed successfully\n");
    return 0;
}
