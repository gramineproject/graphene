#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 *  USAGE:
 *      ./test_start [prefixes to the program ...]
 *
 *  EXAMPLES:
 *      ./test_start                => native start time
 *      ./test_start ./libpal.so    => graphene start time
 */

#define OVERHEAD_TIMES 30000
#define TEST_TIMES     30

void get_time(char* time_arg, unsigned long overhead) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    unsigned long long msec = tv.tv_sec * 1000000ULL + tv.tv_usec;
    snprintf(time_arg, 30, "%llu", msec + overhead);
}

int main(int argc, char** argv, char** envp) {
    char* new_argv[argc + 2];
    char time_arg[30];

    for (int i = 1; i < argc; i++) {
        new_argv[i - 1] = argv[i];
    }

    new_argv[argc - 1] = "./start.pthread.m";
    new_argv[argc]     = time_arg;
    new_argv[argc + 1] = NULL;

    unsigned long long times[TEST_TIMES];
    unsigned long long sum = 0, ssum = 0;
    memset(times, 0, sizeof(times));

    for (int i = 1; i < TEST_TIMES; i++) {
        int pipes[2];
        if (pipe(pipes) < 0)
            break;

        pid_t pid = fork();

        if (pid < 0)
            break;

        if (!pid) {
            struct timeval tv1, tv2;
            gettimeofday(&tv1, NULL);
            for (int j = 0; j < OVERHEAD_TIMES; j++) {
                get_time(time_arg, 0);
            }
            gettimeofday(&tv2, NULL);
            unsigned long long msec1    = tv1.tv_sec * 1000000ULL + tv1.tv_usec;
            unsigned long long msec2    = tv2.tv_sec * 1000000ULL + tv2.tv_usec;
            unsigned long long overhead = (msec2 - msec1) / OVERHEAD_TIMES;

            close(pipes[0]);
            dup2(pipes[1], 1);

            get_time(time_arg, overhead);

            execve(new_argv[0], new_argv, envp);
            exit(-1);
        }

        close(pipes[1]);

        int status;
        waitpid(pid, &status, 0);

        if (read(pipes[0], time_arg, 30) < 0)
            break;

        times[i] = atoll(time_arg);
        sum += times[i];
        ssum += times[i] * times[i];

        close(pipes[0]);
    }

    int compar(const void* arg1, const void* arg2) {
        register unsigned long long a1 = *((unsigned long long*)arg1);
        register unsigned long long a2 = *((unsigned long long*)arg2);
        return a1 < a2 ? -1 : (a1 == a2 ? 0 : 1);
    }

    qsort(times, TEST_TIMES, sizeof(unsigned long long), compar);

    double median = (TEST_TIMES % 2)
                        ? (double)times[TEST_TIMES / 2]
                        : (double)(times[TEST_TIMES / 2 - 1] + times[TEST_TIMES / 2]) / 2;

    double mean   = (double)sum / TEST_TIMES;
    double stddev = sqrt((double)ssum / TEST_TIMES - mean * mean);
    double ci     = 1.96 * stddev / sqrt((double)TEST_TIMES);

    printf("median = %lf, mean = %lf (+/-%lf)\n", median, mean, ci);

    return 0;
}
