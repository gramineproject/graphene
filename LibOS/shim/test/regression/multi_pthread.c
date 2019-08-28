#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define THREAD_NUM      32
#define CONC_THREAD_NUM 4

atomic_int counter = 0;

void* inc(void* arg) {
    counter++;
    return NULL;
}

int main(int argc, char** argv) {
    for (int i = 0; i < THREAD_NUM; i++) {
        pthread_t thread[CONC_THREAD_NUM];

        /* create several threads running in parallel */
        for (int j = 0; j < CONC_THREAD_NUM; j++) {
            pthread_create(&thread[j], NULL, inc, NULL);
        }

        /* join threads and continue with the next batch */
        for (int j = 0; j < CONC_THREAD_NUM; j++) {
            pthread_join(thread[j], NULL);
        }
    }

    printf("%d Threads Created\n", counter);
    return 0;
}
