/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* a simple helloworld test, with pthread usage */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

#define THREAD_NUMBER 128

int counter = 0;

void * inc (void *arg)
{
//    printf("%dth thread, child: pid %d\n", counter++, getpid());
    counter++;
    return NULL;
}

int main(int argc, char ** argv)
{
    pthread_t thread;
//    printf("parent: pid %d\n", getpid());
    for (int i = 0; i < THREAD_NUMBER; i++){
      pthread_create(&thread, NULL, inc, NULL);
      pthread_join(thread, NULL);
    }
    printf("%d Threads Created\n", counter);
    return 0;
}
