/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/time.h>

int firstpid;
int secondpid;

#define NTRIES    10000

int count = 0;

void sighand1 (int signum, siginfo_t * sinfo, void * ucontext)
{
    count++;
    printf("firstpid receive a SIGUSR from %d (count = %d)\n",
           sinfo->si_pid, count);
    kill(secondpid, SIGUSR1);
}

void sighand2 (int signum, siginfo_t * sinfo, void * ucontext)
{
    count++;
    printf("secondpid receive a SIGUSR from %d (count = %d)\n",
           sinfo->si_pid, count);
    kill(firstpid, SIGUSR1);
}

int main(int argc, char ** argv)
{
    int pipes[2];

    pipe(pipes);

    firstpid = fork();

    if (firstpid < 0) {
        printf("fork failed\n");
        return -1;
    }

    if (firstpid == 0) {
        close(pipes[1]);

        struct timeval start_time;
        gettimeofday(&start_time, NULL);

        signal(SIGUSR1, (void *) sighand1);
        read(pipes[0], &secondpid, sizeof(int));
        kill(secondpid, SIGUSR1);
        while (count < NTRIES - 1)
            sleep(1);

        struct timeval finish_time;
        gettimeofday(&finish_time, NULL);

        printf("time spent: %lu microsecond\n",
               (finish_time.tv_sec * 1000000L + finish_time.tv_usec)
               - (start_time.tv_sec * 1000000L + start_time.tv_usec));

        return 0;
    }

    close(pipes[0]);

    secondpid = fork();

    if (secondpid < 0) {
        printf("fork failed\n");
        return -1;
    }

    if (secondpid == 0) {
        struct timeval start_time;
        gettimeofday(&start_time, NULL);

        signal(SIGUSR1, (void *) sighand2);
        secondpid = getpid();
        write(pipes[1], &secondpid, sizeof(int));
        while (count < NTRIES)
            sleep(1);

        struct timeval finish_time;
        gettimeofday(&finish_time, NULL);

        printf("time spent: %lu microsecond\n",
               (finish_time.tv_sec * 1000000L + finish_time.tv_usec)
               - (start_time.tv_sec * 1000000L + start_time.tv_usec));

        return 0;
    }

    waitpid(-1, NULL, 0);
    waitpid(-1, NULL, 0);

    return 0;
}
