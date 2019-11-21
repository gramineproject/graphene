#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

void * thread_func(void * arg)
{
    exit(113);
    return NULL;
}

int main(int argc, char * argv[])
{
    sigset_t newmask;
    sigemptyset(&newmask);
    sigaddset(&newmask, SIGKILL);
    sigaddset(&newmask, SIGSTOP);

    int ret = sigprocmask(SIG_SETMASK, &newmask, NULL);

    if (ret < 0) {
        perror("sigprocmask failed");
        return -1;
    }
 
    pthread_t thread;
    ret = pthread_create(&thread, NULL, thread_func, NULL);
    if (ret < 0) {
        perror("pthread_create failed");
        return -1;
    }

    while(1)
        sleep (1);

    return -1;
}
