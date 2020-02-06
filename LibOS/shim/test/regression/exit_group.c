#define _XOPEN_SOURCE 700
#include <linux/unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define THREAD_NUM 4

atomic_int counter = 1;

pthread_barrier_t barrier;

/* Test the process exit logic in Graphene. Multiple threads race to execute exit()/exit_group().
 * Expected return code is 0 .. 4, depending on which thread wins. */

void* inc(void* arg) {
    int a = counter++;
    pthread_barrier_wait(&barrier);
    exit(a);
}

int main(int argc, char** argv) {
    pthread_t thread[THREAD_NUM];
    pthread_barrier_init(&barrier, NULL, THREAD_NUM + 1);

    for (int j = 0; j < THREAD_NUM; j++) {
        pthread_create(&thread[j], NULL, inc, NULL);
    }

    pthread_barrier_wait(&barrier);
    return 0;
}
