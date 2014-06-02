/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

void * print2(void * arg)
{
    printf("This is Function 2 - go to sleep\n");
    sleep(5);
    printf("Function2 out of sleep\n");
    printf("%s",(char *) arg);
    return NULL;
}

void * print (void *arg)
{
    printf("This is Function 1 - go to sleep\n");
    sleep(5);
    printf("Function1 out of sleep\n");
    printf("%s",(char *) arg);
    return NULL;
}

void * TestFunc(void * arg )
{
    int * ptr = (int *) arg;
    printf("Parent gave %d\n",*ptr);
}

int main(int argc, char ** argv) {
    pthread_t threadId1,threadId2,threadId3;
    int intvar = 12;

    printf("MANISAYS :The Functions are at %p %p %p \n",print,print2,TestFunc);
    pthread_create(&threadId1, NULL, print, "Thread1 Executing ...\n");
    //sleep(2);
    pthread_create(&threadId2, NULL, print2, "Thread2 Executing ...\n");
    //sleep(2);
    pthread_create(&threadId3, NULL, TestFunc,&intvar);
    printf("going to sleep\n");
    //sleep(2);
    printf("out of sleep\n");
    pthread_join(threadId1, NULL);
    pthread_join(threadId2, NULL);
    pthread_join(threadId3, NULL);
    return 0;
}
