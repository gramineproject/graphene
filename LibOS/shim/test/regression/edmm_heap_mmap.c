/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation */

#define _GNU_SOURCE
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

#define min(a, b)               (((a) < (b)) ? (a) : (b))
#define MAIN_THREAD_CNT         1
#define INTERNAL_THREAD_CNT     2
#define MANIFEST_SGX_THREAD_CNT 16 /* corresponds to sgx.thread_num in the manifest template */

/* barrier to synchronize between parent and children */
pthread_barrier_t barrier;

static pid_t mygettid(void) {
    return syscall(SYS_gettid);
}

double g_per_mmap_diff[MANIFEST_SGX_THREAD_CNT] = {0};
double g_per_munmap_diff[MANIFEST_SGX_THREAD_CNT] = {0};

static void mmap_munmap_memory(int val) {
    size_t mmap_length = 0x4000;
    struct timeval tv1 = {0};
    struct timeval tv2 = {0};
    long long mmap_diff;
    long long munmap_diff;

    for (int i = 0; i < 500; i++) {
        if (gettimeofday(&tv1, NULL)) {
            printf("Cannot get time 1: %m\n");
        }
        void* a = mmap(NULL, mmap_length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                      -1, 0);
        if (a == MAP_FAILED) {
            err(EXIT_FAILURE, "mmap failed for tid=%d for size 0x%lx\n",  mygettid(),
                 mmap_length);
        }
        if (gettimeofday(&tv2, NULL)) {
            printf("Cannot get time 2: %m\n");
        }

        mmap_diff += ((tv2.tv_sec - tv1.tv_sec) * 1000000ll);
        mmap_diff += tv2.tv_usec - tv1.tv_usec;

        memset(a, val, mmap_length);
        if (gettimeofday(&tv1, NULL)) {
            printf("Cannot get time 1: %m\n");
        }
        int rv = munmap(a, mmap_length);
        if (rv) {
            err(EXIT_FAILURE, "munmap failed for tid =%d for size 0x%lx\n",  mygettid(),
                 mmap_length);
        }
        if (gettimeofday(&tv2, NULL)) {
            printf("Cannot get time 2: %m\n");
        }

        munmap_diff += ((tv2.tv_sec - tv1.tv_sec) * 1000000ll);
        munmap_diff += tv2.tv_usec - tv1.tv_usec;
    }

    int tid = mygettid();
    assert(tid);
    g_per_mmap_diff[tid-1] = ((double)(mmap_diff/500))/1000;
    g_per_munmap_diff[tid-1] = ((double)(munmap_diff/500))/1000;
}

/* Run a busy loop for some iterations, so that we can verify affinity with htop manually */
static void* dowork(void* args) {
    uint32_t val = *(uint32_t*)args;

    mmap_munmap_memory(val);

    /* child waits on barrier */
    int ret = pthread_barrier_wait(&barrier);
    if (ret != 0 && ret != PTHREAD_BARRIER_SERIAL_THREAD) {
        errx(EXIT_FAILURE, "Child did not wait on barrier!");
    }

    return NULL;
}

static int run(int sgx_thread_cnt) {
    int ret;
    long numprocs = sysconf(_SC_NPROCESSORS_ONLN);
    if (numprocs < 0) {
        err(EXIT_FAILURE, "Failed to retrieve the number of logical processors!");
    }

    /* If you want to run on all cores then increase sgx.thread_num in the manifest.template and
     * also set MANIFEST_SGX_THREAD_CNT to the same value.
     */
    numprocs = min(numprocs, (sgx_thread_cnt - (INTERNAL_THREAD_CNT + MAIN_THREAD_CNT)));
    printf("NO. of threads created = %ld\n", numprocs);

    pthread_t* threads = (pthread_t*)malloc(numprocs * sizeof(pthread_t));
    if (!threads) {
         errx(EXIT_FAILURE, "memory allocation failed");
    }

    /*per-thread unique values */
    int* per_thread_val = (int*)malloc(numprocs * sizeof(int));
    if (!per_thread_val) {
         errx(EXIT_FAILURE, "per-thread memory allocation failed");
    }

    if (pthread_barrier_init(&barrier, NULL, numprocs + 1)) {
        free(threads);
        errx(EXIT_FAILURE, "pthread barrier init failed");
    }

    /* Validate parent set/get affinity for child */
    for (uint32_t i = 0; i < numprocs; i++) {
        per_thread_val[i] = i + 1;
        ret = pthread_create(&threads[i], NULL, dowork, (void*)&per_thread_val[i]);
        if (ret != 0) {
            free(threads);
            errx(EXIT_FAILURE, "pthread_create failed!");
        }
    }

    /* parent waits on barrier */
    ret = pthread_barrier_wait(&barrier);
    if (ret != 0 && ret != PTHREAD_BARRIER_SERIAL_THREAD) {
        free(threads);
        errx(EXIT_FAILURE, "Parent did not wait on barrier!");
    }

    mmap_munmap_memory(0);

    for (int i = 0; i < numprocs; i++) {
        ret = pthread_join(threads[i], NULL);
        if (ret != 0) {
            free(threads);
            errx(EXIT_FAILURE, "pthread_join failed!");
        }
    }

    /* Validating parent set/get affinity for children done. Free resources */
    pthread_barrier_destroy(&barrier);
    free(per_thread_val);
    free(threads);

    double total_mmap_diff = 0;
    double total_munmap_diff = 0;
    for (int i = 1; i < numprocs+1; i++) {
        printf("Average mmap_time(ms): %lf, munmap_time(ms): %lf for thread %d\n",
                g_per_mmap_diff[i], g_per_munmap_diff[i], i);
        total_mmap_diff += g_per_mmap_diff[i];
        total_munmap_diff += g_per_munmap_diff[i];
    }
    printf("Avg across all threads, mmap_time(ms): %lf, munmap_time(ms): %lf\n",
           (float)(total_mmap_diff/numprocs), (float)(total_munmap_diff/numprocs) );

    printf("===================================================================================\n");
    return 0;
}

#define MAX_THREADS 64
int main(int argc, const char** argv) {

    int num_threads = min(MAX_THREADS, MANIFEST_SGX_THREAD_CNT);
    /*Run tests for 1, 2, 4, 8 ...threads until num_threads */
    for (int i = 1, j = 4; j < num_threads; i++) {
        run(j);
        j = pow(2, i) + INTERNAL_THREAD_CNT + MAIN_THREAD_CNT;
        sleep(5);
    }

    printf("TEST OK\n");
    return 0;
}