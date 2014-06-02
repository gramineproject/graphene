/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* a simple helloworld test, with pthread usage */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

void * print (void *arg)
{
    printf("child: pid %d\n", getpid());
    puts((char *) arg);
    return NULL;
}

int main(int argc, char ** argv)
{
    pthread_t thread;
    printf("parent: pid %d\n", getpid());
    pthread_create(&thread, NULL, print, "Hello World!");
    pthread_join(thread, NULL);
    return 0;
}
