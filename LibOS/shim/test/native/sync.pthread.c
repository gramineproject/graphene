/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <pthread.h>
#include <stdio.h>
#include <math.h>

#define ITERATIONS 100000

// A shared mutex
pthread_mutex_t mutex;
double target;

void* opponent(void *arg)
{
    int i ;
    for(i = 0; i < ITERATIONS; ++i)
    {
        // Lock the mutex
        pthread_mutex_lock(&mutex);
        target -=  i ;
        // Unlock the mutex
        pthread_mutex_unlock(&mutex);
    }

    return NULL;
}

int main(int argc, char **argv)
{
    pthread_t other;
    int rv;

    target = 5.0;

    // Initialize the mutex
    if(pthread_mutex_init(&mutex, NULL))
    {
        printf("Unable to initialize a mutex\n");
        return -1;
    }

    if(pthread_create(&other, NULL, &opponent, NULL))
    {
        printf("Unable to spawn thread\n");
        return -1;
    }


    int i;
    for(i = 0; i < ITERATIONS; ++i)
    {
        pthread_mutex_lock(&mutex);
        target +=  i ;
        pthread_mutex_unlock(&mutex);
    }

    if(rv = pthread_join(other, NULL))
    {
        printf("Could not join thread - %d\n", rv);
        return -1;
    }

    // Clean up the mutex
    pthread_mutex_destroy(&mutex);

    printf("Result: %f\n", target);

    return 0;
}
