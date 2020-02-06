#define _XOPEN_SOURCE 700
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

int firstpid;
int secondpid;

#define NTRIES     1000
#define TEST_TIMES 32
#define DO_BENCH   1

int count = 0;

void sighand1(int signum) {
    count++;
#ifndef DO_BENCH
    printf("%d receive a SIGUSR (count = %d)\n", getpid(), count);
#endif
    kill(secondpid, SIGUSR1);
}

void sighand2(int signum) {
    count++;
#ifndef DO_BENCH
    printf("%d receive a SIGUSR (count = %d)\n", getpid(), count);
#endif
    kill(firstpid, SIGUSR1);
}

int main(int argc, char** argv) {
    int times = TEST_TIMES;

    for (int i = 0; i < times; i++) {
        int pipes[2];

        if (pipe(pipes) < 0) {
            perror("pipe error");
            return 1;
        }

        firstpid = fork();

        if (firstpid < 0) {
            printf("fork failed\n");
            return 1;
        }

        if (firstpid == 0) {
            close(pipes[1]);

            signal(SIGUSR1, sighand1);
            if (read(pipes[0], &secondpid, sizeof(int)) != sizeof(int)) {
                perror("read error");
                return 1;
            }
#ifndef DO_BENCH
            printf("%d killing %d\n", getpid(), secondpid);
#endif
            struct timeval start_time;
            gettimeofday(&start_time, NULL);
            kill(secondpid, SIGUSR1);
            while (count < NTRIES - 1) {
                sleep(1);
            }

            struct timeval finish_time;
            gettimeofday(&finish_time, NULL);

            printf("%d time spent: %lu microsecond\n", getpid(),
                   (finish_time.tv_sec * 1000000L + finish_time.tv_usec) -
                       (start_time.tv_sec * 1000000L + start_time.tv_usec));

            exit(0);
        }

        close(pipes[0]);

        secondpid = fork();

        if (secondpid < 0) {
            printf("fork failed\n");
            return 1;
        }

        if (secondpid == 0) {
            signal(SIGUSR1, sighand2);
            secondpid = getpid();
            if (write(pipes[1], &secondpid, sizeof(int)) != sizeof(int)) {
                perror("write error");
                return 1;
            }
            struct timeval start_time;
            gettimeofday(&start_time, NULL);

            while (count < NTRIES) sleep(1);

            struct timeval finish_time;
            gettimeofday(&finish_time, NULL);

            printf("%d time spent: %lu microsecond\n", getpid(),
                   (finish_time.tv_sec * 1000000L + finish_time.tv_usec) -
                       (start_time.tv_sec * 1000000L + start_time.tv_usec));

            exit(0);
        }
    }
    return 0;
}
