#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#define DO_BENCH   1
#define NTRIES     100
#define TEST_TIMES 64

int pids[TEST_TIMES];

int main(int argc, char** argv) {
    int times = TEST_TIMES;
    int pipes[6];
    int i = 0;

    if (argc >= 2) {
        times = atoi(argv[1]);
        if (times > TEST_TIMES)
            return 1;
    }

    if (pipe(&pipes[0]) < 0 || pipe(&pipes[2]) < 0 || pipe(&pipes[4]) < 0) {
        perror("pipe error");
        return 1;
    }

    for (i = 0; i < times; i++) {
        pids[i] = fork();

        if (pids[i] < 0) {
            printf("fork failed\n");
            return 1;
        }

        if (pids[i] == 0) {
            close(pipes[1]);
            close(pipes[2]);
            close(pipes[5]);

            char byte;
            if (read(pipes[0], &byte, 1) != 1) {
                perror("read error");
                return 1;
            }

            struct timeval timevals[2];
            gettimeofday(&timevals[0], NULL);

            for (int count = 0; count < NTRIES; count++) {
                int child = fork();

                if (!child)
                    exit(0);

                if (child > 0)
                    waitpid(child, NULL, 0);
            }

            gettimeofday(&timevals[1], NULL);

            close(pipes[0]);

            if (write(pipes[3], timevals, sizeof(struct timeval) * 2)
                    != sizeof(struct timeval) * 2) {
                perror("write error");
                return 1;
            }
            close(pipes[3]);

            if (read(pipes[4], &byte, 1) != 1) {
                perror("read error");
                return 1;
            }
            close(pipes[4]);
            exit(0);
        }
    }

    close(pipes[0]);
    close(pipes[3]);
    close(pipes[4]);

    sleep(1);
    char bytes[times];
    if (write(pipes[1], bytes, times) != times) {
        perror("write error");
        return 1;
    }
    close(pipes[1]);

    unsigned long long start_time = 0;
    unsigned long long end_time   = 0;
    unsigned long long total_time = 0;
    struct timeval timevals[2];
    for (int i = 0; i < times; i++) {
        if (read(pipes[2], timevals, sizeof(struct timeval) * 2) != sizeof(struct timeval) * 2) {
            perror("read error");
            return 1;
        }
        unsigned long s = timevals[0].tv_sec * 1000000ULL + timevals[0].tv_usec;
        unsigned long e = timevals[1].tv_sec * 1000000ULL + timevals[1].tv_usec;
        if (!start_time || s < start_time)
            start_time = s;
        if (!end_time || e > end_time)
            end_time = e;
        total_time += e - s;
    }
    close(pipes[2]);

    if (write(pipes[5], bytes, times) != times) {
        perror("write error");
        return 1;
    }
    close(pipes[5]);

    for (i = 0; i < times; i++) {
        waitpid(pids[i], NULL, 0);
    }

    printf(
        "%d processes fork %d children: throughput = %lf procs/second, "
        "latency = %lf microseconds\n",
        times, NTRIES, 1.0 * NTRIES * times * 1000000 / (end_time - start_time),
        1.0 * total_time / (NTRIES * times));

    return 0;
}
