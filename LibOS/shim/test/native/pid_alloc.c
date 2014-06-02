/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#define __USE_GNU
#include <sched.h>
#include <sys/wait.h>
#include <sys/time.h>

int func (void *arg)
{
    return 0;
}

int main(int argc, char ** argv)
{
    for (int i = 0 ; i < 20 ; i++) {
        int pid = fork();

        if (pid < 0) {
            printf("fork failed\n");
            return -1;
        }

        if (pid == 0) {
            pid = getpid();

            struct timeval start_time;
            gettimeofday(&start_time, NULL);

            for (int j = 0 ; j < 512 ; j++) {
                void * stack = malloc(4096);

                int child = clone(&func, stack + 4088,
                                  CLONE_FS|CLONE_FILES|CLONE_SIGHAND|
                                  CLONE_VM|CLONE_SYSVSEM,
                                  NULL);
                printf("created by %d: %d\n", pid, child);
                waitpid(child, NULL, 0);
            }

            struct timeval finish_time;
            gettimeofday(&finish_time, NULL);

            printf("time spent: %lu microsecond\n",
                   (finish_time.tv_sec * 1000000L + finish_time.tv_usec)
                   - (start_time.tv_sec * 1000000L + start_time.tv_usec));

            return 0;
        }
    }

    return 0;
}
