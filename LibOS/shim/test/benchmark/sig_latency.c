#define _XOPEN_SOURCE 700
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#define DO_BENCH
#define NTRIES     1000
#define TEST_TIMES 32

int count = 0;
int pids[TEST_TIMES][2];
int firstpid;
int secondpid;

void sighand1(int signum, siginfo_t* sinfo, void* ucontext) {
    count++;
#ifndef DO_BENCH
    if (count % 100 == 0)
        printf("Received a SIGUSR1 (%d) (count = %d) from %d\n", signum, count, sinfo->si_pid);
#endif
    if (count > NTRIES)
        return;

    kill(secondpid, SIGUSR1);
}

void sighand2(int signum, siginfo_t* sinfo, void* ucontext) {
    count++;
#ifndef DO_BENCH
    if (count % 100 == 0)
        printf("Received a SIGUSR1 (%d) (count = %d) from %d\n", signum, count, sinfo->si_pid);
#endif
    if (count > NTRIES)
        return;

    kill(firstpid, SIGUSR1);
}

void (*sighand)(int signum, siginfo_t* sinfo, void* ucontext) = NULL;

void sigact(int signum, siginfo_t* sinfo, void* ucontext) {
    if (sighand)
        sighand(signum, sinfo, ucontext);
}

int main(int argc, char** argv) {
    int times = TEST_TIMES;
    int pipes[8];
    int i = 0;

    if (argc >= 2) {
        times = atoi(argv[1]) / 2;
        if (times > TEST_TIMES)
            return 1;
    }

    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGUSR1, (void*)sigact);

    if (pipe(&pipes[0]) < 0 || pipe(&pipes[2]) < 0 || pipe(&pipes[4]) < 0 || pipe(&pipes[6]) < 0) {
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
            sighand = sighand1;

            close(pipes[0]);
            close(pipes[1]);
            close(pipes[3]);
            close(pipes[4]);
            close(pipes[7]);

            count = 0;
            if (read(pipes[6], &pids[i][1], sizeof(int)) != sizeof(int)) {
                perror("read error");
                return 1;
            }
            secondpid = pids[i][1];
            close(pipes[6]);

            char byte;
            if (write(pipes[5], &byte, 1) != 1) {
                perror("write error");
                return 1;
            }
            close(pipes[5]);

            while (count < NTRIES) {
                sched_yield();
            }

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
            sighand = sighand2;

            close(pipes[1]);
            close(pipes[3]);
            close(pipes[4]);
            close(pipes[6]);

            firstpid = pids[i][0];
            int pid  = getpid();
            if (write(pipes[7], &pid, sizeof(int)) != sizeof(int)) {
                perror("write error");
                return 1;
            }
            close(pipes[7]);

            char byte;
            if (write(pipes[5], &byte, 1) != 1) {
                perror("write error");
                return 1;
            }
            if (read(pipes[0], &byte, 1) != 1) {
                perror("read error");
                return 1;
            }

            struct timeval timevals[2];
            gettimeofday(&timevals[0], NULL);

            count = 0;
            kill(firstpid, SIGUSR1);

            while (count < NTRIES - 1) {
                sched_yield();
            }

            gettimeofday(&timevals[1], NULL);

            close(pipes[0]);

            if (write(pipes[5], timevals, sizeof(struct timeval) * 2) != sizeof(struct timeval) * 2) {
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
    close(pipes[6]);
    close(pipes[7]);

    for (int i = 0; i < times * 2; i++) {
        char i;
        while (read(pipes[4], &i, 1) < 0)
            ;
    }

    printf("all processes ready\n");
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
        while (read(pipes[4], timevals, sizeof(struct timeval) * 2) < 0)
            ;
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

    printf("throughput for %d processes to send %d signals: %lf signals/second\n", times, NTRIES,
           1.0 * NTRIES * 2 * times * 1000000 / (end_time - start_time));

    return 0;
}
