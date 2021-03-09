#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>

#define THREAD_NUM 4
#define ITERATIONS 1000000

struct timeval base_tv;
struct timeval tv[THREAD_NUM];

static void* foo(void* arg) {
    int ret;
    size_t idx = (size_t)arg;

    for (size_t i = 0; i < ITERATIONS; i++) {
        ret = gettimeofday(&tv[idx], NULL);
        if (ret < 0)
            err(1, "thread gettimeofday");

        if (tv[idx].tv_sec < base_tv.tv_sec || tv[idx].tv_sec - base_tv.tv_sec > 20)
            errx(1, "Retrieved time is more than 20 seconds away from base time");
    }

    return NULL;
}

int main(int argc, char** argv) {
    int ret;

    ret = gettimeofday(&base_tv, NULL);
    if (ret < 0)
        err(1, "base gettimeofday");

    printf("Starting time: %lu sec, %lu usec\n", base_tv.tv_sec, base_tv.tv_usec);

    pthread_t thread[THREAD_NUM];
    for (size_t i = 0; i < THREAD_NUM; i++) {
        pthread_create(&thread[i], NULL, foo, (void*)i);
    }
    for (size_t i = 0; i < THREAD_NUM; i++) {
        pthread_join(thread[i], NULL);
    }

    struct timeval end_tv;
    ret = gettimeofday(&end_tv, NULL);
    if (ret < 0)
        err(1, "base gettimeofday");

    uint64_t usec_diff = end_tv.tv_usec > base_tv.tv_usec ? end_tv.tv_usec - base_tv.tv_usec
                                                          : base_tv.tv_usec - end_tv.tv_usec;
    printf("Finish time: %lu sec, %lu usec (passed: %lu sec, %lu usec)\n", end_tv.tv_sec,
           end_tv.tv_usec, end_tv.tv_sec - base_tv.tv_sec, usec_diff);
    puts("TEST OK");
    return 0;
}
