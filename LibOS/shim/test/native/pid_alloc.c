#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <sys/time.h>
#include <sys/wait.h>

int func(void* arg) {
    return 0;
}

int main(int argc, char** argv) {
    for (int i = 0; i < 20; i++) {
        int pid = fork();

        if (pid < 0) {
            printf("fork failed\n");
            return -1;
        }

        if (pid == 0) {
            pid = getpid();

            struct timeval start_time;
            gettimeofday(&start_time, NULL);

            for (int j = 0; j < 512; j++) {
                void* stack = malloc(4096);

                int child =
                    clone(&func, stack + 4088,
                          CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_VM | CLONE_SYSVSEM, NULL);
                printf("created by %d: %d\n", pid, child);
                waitpid(child, NULL, 0);
            }

            struct timeval finish_time;
            gettimeofday(&finish_time, NULL);

            printf("time spent: %lu microsecond\n",
                   (finish_time.tv_sec * 1000000L + finish_time.tv_usec) -
                       (start_time.tv_sec * 1000000L + start_time.tv_usec));

            return 0;
        }
    }

    return 0;
}
