#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

pthread_mutex_t count_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t condvar      = PTHREAD_COND_INITIALIZER;

void* function1();
void* function2();
int count = 0;

#define COUNT_DONE  10
#define COUNT_HALT1 3
#define COUNT_HALT2 6

int main(int argc, const char** argv) {
    pthread_t thread1, thread2;

    pthread_create(&thread1, NULL, &function1, NULL);
    pthread_create(&thread2, NULL, &function2, NULL);

    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    printf("Final count: %d\n", count);
    return 0;
}

void* function1(void) {
    for (;;) {
        // Lock mutex and then wait for signal to relase mutex
        pthread_mutex_lock(&count_mutex);

        // Wait while functionCount2() operates on count
        // mutex unlocked if condition varialbe in functionCount2() signaled.
        pthread_cond_wait(&condvar, &count_mutex);
        count++;
        printf("Counter value in function1: %d\n", count);

        pthread_mutex_unlock(&count_mutex);

        if (count >= COUNT_DONE)
            return NULL;
    }
}

void* function2(void) {
    for (;;) {
        pthread_mutex_lock(&count_mutex);

        if (count < COUNT_HALT1 || count > COUNT_HALT2) {
            // Condition of if statement has been met.
            // Signal to free waiting thread by freeing the mutex.
            // Note: functionCount1() is now permitted to modify "count".
            pthread_cond_signal(&condvar);
        } else {
            count++;
            printf("Counter value function2: %d\n", count);
        }

        pthread_mutex_unlock(&count_mutex);

        if (count >= COUNT_DONE)
            return NULL;
    }
}
