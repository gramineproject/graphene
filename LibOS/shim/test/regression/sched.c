#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/time.h>

/* This test checks that our dummy implementations work correctly. None of the
 * below syscalls are actually propagated to the host OS or change anything.\
 * NOTE: This test works correctly only on Graphene (not on Linux). */

int main(int argc, char** argv) {
    /* setters */
    struct sched_param param = {.sched_priority = 50};
    if (sched_setscheduler(0, SCHED_RR, &param) == -1) {
        perror("Error setting scheduler\n");
        return 1;
    }

    if (sched_setparam(0, &param) == -1) {
        perror("Error setting param\n");
        return 1;
    }

    if (setpriority(PRIO_PROCESS, 0, 10) == -1) {
        perror("Error setting priority\n");
        return 1;
    }

    cpu_set_t my_set;
    CPU_ZERO(&my_set);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &my_set) == -1) {
        perror("Error setting affinity\n");
        return 1;
    }

    /* getters */
    if (sched_getscheduler(0) != SCHED_OTHER) {
        perror("Error getting scheduler\n");
        return 2;
    }

    if (sched_getparam(0, &param) == -1 || param.sched_priority != 0) {
        perror("Error getting param\n");
        return 2;
    }

    if (getpriority(PRIO_PROCESS, 0) != 0) {
        perror("Error getting priority\n");
        return 2;
    }

    if (sched_getaffinity(0, sizeof(cpu_set_t), &my_set) == -1) {
        perror("Error getting affinity\n");
        return 2;
    }

    if (sched_get_priority_max(SCHED_FIFO) != 99) {
        perror("Error getting max priority of SCHED_FIFO\n");
        return 2;
    }

    if (sched_get_priority_min(SCHED_FIFO) != 1) {
        perror("Error getting min priority of SCHED_FIFO\n");
        return 2;
    }

    struct timespec interval = {0};
    if (sched_rr_get_interval(0, &interval) == -1 || interval.tv_sec != 0 ||
            interval.tv_nsec != 100000000) {
        perror("Error getting interval of SCHED_RR\n");
        return 2;
    }

    puts("Test completed successfully");
    return 0;
}
