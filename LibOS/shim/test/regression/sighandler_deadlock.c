#define _XOPEN_SOURCE 700
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

static int received = 0;
#define SIGNAL     (SIGUSR1)
#define NUM_SIGNAL (20000)
static struct timeval *p_timeval = NULL;
static void handler(int sig) {
    if (sig == SIGNAL) {
        received++;
        int ret = gettimeofday(p_timeval, NULL);
        if (ret != 0) {
            fprintf(stderr, "handler received the signal, receive = %d ret %d, errno %d/%s \n", received, ret,
                   errno, strerror(errno));
            return;
        }
        printf("handler received the signal, receive = %d\n", received);
    }
}

int main() {
    int count = 0;

    pid_t pid2 = fork();
    if (pid2 < 0)
        fprintf(stderr, "failed to create child process\n");
    else if (pid2 == 0) {  // child
        p_timeval = malloc(sizeof(*p_timeval));
        struct sigaction new_action;
        new_action.sa_handler = handler;
        sigemptyset(&new_action.sa_mask);
        new_action.sa_flags = 0;
        int sigret = sigaction(SIGNAL, &new_action, NULL);
        if (sigret < 0) {
            fprintf(stderr, "sigaction failed, sigret = %d\n", sigret);
            return 1;
        }
        struct timeval start;
        int last_received = 0;
        while (received < NUM_SIGNAL) {
            if (received != last_received) {
                printf("SIGNAL received = %d.\n", received);
                last_received = received;
            }
            int ret = gettimeofday(&start, NULL);
            if (ret != 0) {
                fprintf(stderr, "child main, gettimeofdata failed %d\n", ret);
            }
        }

        printf("child to exit received  %d\n", received);
        free(p_timeval);
        p_timeval = NULL;
    } else {  // parent
        sleep(5);
        while (count <= NUM_SIGNAL) {
            sleep(1);
            kill(pid2, SIGNAL);
            printf("kill count = %d\n", count);
            count ++;
        }
        printf("parent to exit\n");
    }

    return 0;
}
