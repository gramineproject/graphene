#define _XOPEN_SOURCE 700
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void* thread_func(void* arg) {
    exit(113);
    return NULL;
}

int main(int argc, char* argv[]) {
    sigset_t newmask;
    sigset_t oldmask;
    sigemptyset(&newmask);
    sigemptyset(&oldmask);
    sigaddset(&newmask, SIGKILL);
    sigaddset(&newmask, SIGSTOP);

    int ret = sigprocmask(SIG_SETMASK, &newmask, NULL);

    if (ret < 0) {
        perror("sigprocmask failed");
        return -1;
    }

    ret = sigprocmask(SIG_SETMASK, NULL, &oldmask);
    if (ret < 0) {
        perror("sigprocmask failed");
        return -1;
    }

    if (sigismember(&oldmask, SIGKILL) || sigismember(&oldmask, SIGSTOP)) {
        printf("SIGKILL or SIGSTOP should be ignored, but not.\n");
        return -1;
    }

    pthread_t thread;
    ret = pthread_create(&thread, NULL, thread_func, NULL);
    if (ret < 0) {
        perror("pthread_create failed");
        return -1;
    }

    while (1)
        sleep(1);

    return -1;
}
