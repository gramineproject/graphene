/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

void * print1 (void *arg)
{
    printf("This is Function 1 - go to sleep\n");
    sleep(5);
    printf("Function1 out of sleep\n");
    printf("%s",(char *) arg);
    return NULL;
}

void * print2(void * arg)
{
    printf("This is Function 2 - go to sleep\n");
    sleep(5);
    printf("Function2 out of sleep\n");
    printf("%s",(char *) arg);
    return NULL;
}

void * func(void * arg )
{
    int * ptr = (int *) arg;
    printf("Parent gave %d\n",*ptr);
}

int main(int argc, char ** argv)
{
    pthread_t thread1, thread2,thread3;
    int intvar = 12;

    pthread_create(&thread1, NULL, print1, "Thread1 Executing ...\n");
    pthread_create(&thread2, NULL, print2, "Thread2 Executing ...\n");
    pthread_create(&thread3, NULL, func, &intvar);
    printf("going to sleep\n");
    printf("out of sleep\n");
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
    pthread_join(thread3, NULL);
    return 0;
}
