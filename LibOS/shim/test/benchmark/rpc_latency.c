#include <shim_unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#define NTRIES     10000
#define TEST_TIMES 32

int main(int argc, char** argv) {
    int times = TEST_TIMES;
    int pipes[6];
    int pids[TEST_TIMES][2];
    int i = 0;

    if (argc >= 2) {
        times = atoi(argv[1]) / 2;
        if (times > TEST_TIMES)
            return 1;
    }

    if (pipe(&pipes[0]) < 0 || pipe(&pipes[2]) < 0 || pipe(&pipes[4]) < 0) {
        perror("pipe error");
        return 1;
    }

    for (i = 0; i < times; i++) {
        pids[i][0] = fork();

        if (pids[i][0] < 0) {
            printf("fork failed\n");
            return 1;
        }

        if (pids[i][0] == 0) {
            close(pipes[0]);
            close(pipes[1]);
            close(pipes[3]);
            close(pipes[4]);
            close(pipes[5]);
            char byte;
            if (read(pipes[2], &byte, 1) != 1) {
                perror("read error");
                return 1;
            }
            close(pipes[2]);
            exit(0);
        }

        pids[i][1] = fork();

        if (pids[i][1] < 0) {
            printf("fork failed\n");
            return 1;
        }

        if (pids[i][1] == 0) {
            close(pipes[1]);
            close(pipes[3]);
            close(pipes[4]);
            char byte;
            if (read(pipes[0], &byte, 1) != 1) {
                perror("read error");
                return 1;
            }

            struct timeval timevals[2];
            gettimeofday(&timevals[0], NULL);

            benchmark_rpc(pids[i][0], NTRIES, &byte, 1);

            gettimeofday(&timevals[1], NULL);

            close(pipes[0]);

            if (write(pipes[5], timevals, sizeof(struct timeval) * 2)
                    != sizeof(struct timeval) * 2) {
                perror("write error");
                return 1;
            }
            close(pipes[5]);

            if (read(pipes[2], &byte, 1) != 1) {
                perror("read error");
                return 1;
            }
            close(pipes[2]);

            exit(0);
        }
    }

    close(pipes[0]);
    close(pipes[2]);
    close(pipes[5]);

    sleep(1);
    char bytes[times * 2];
    if (write(pipes[1], bytes, times) != times) {
        perror("write error");
        return 1;
    }
    close(pipes[1]);

    unsigned long long start_time = 0;
    unsigned long long end_time   = 0;
    struct timeval timevals[2];
    for (int i = 0; i < times; i++) {
        if (read(pipes[4], timevals, sizeof(struct timeval) * 2) != sizeof(struct timeval) * 2) {
            perror("read error");
            return 1;
        }
        unsigned long s = timevals[0].tv_sec * 1000000ULL + timevals[0].tv_usec;
        unsigned long e = timevals[1].tv_sec * 1000000ULL + timevals[1].tv_usec;
        if (!start_time || s < start_time)
            start_time = s;
        if (!end_time || e > end_time)
            end_time = e;
    }
    close(pipes[4]);

    if (write(pipes[3], bytes, times * 2) != times * 2) {
        perror("write error");
        return 1;
    }
    close(pipes[3]);

    for (i = 0; i < times; i++) {
        waitpid(pids[i][0], NULL, 0);
        waitpid(pids[i][1], NULL, 0);
    }

    printf("throughput for %d processes to send %d message: %lf bytes/second\n", times, NTRIES,
           1.0 * NTRIES * 2 * times * 1000000 / (end_time - start_time));

    return 0;
}
