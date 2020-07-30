/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * sched_set_get_cpuaffinity.c
 *
 * Implementation of the regression test cases for setting/getting cpu affinity
 * on single core or multiple cores.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, const char** argv) {
    long ret;
    cpu_set_t set_cs, get_cs;
    size_t cpucnt = sysconf(_SC_NPROCESSORS_ONLN);

    for (size_t i = 0; i < cpucnt; i++) {
        printf("Testing processor id: %ld\n", i);
        CPU_ZERO(&set_cs);
        CPU_ZERO(&get_cs);
        CPU_SET(i, &set_cs);
        ret = sched_setaffinity(0, sizeof(set_cs), &set_cs);
        if (ret < 0) {
            printf(" Failed to set affinity for current thread, id: %ld\n", i);
            return 1;
        }
        ret = sched_getaffinity(0, sizeof(get_cs), &get_cs);
        if (ret < 0) {
            printf(" Failed to get affinity for current thread, id: %ld\n", i);
            return 1;
        }
        if (!CPU_EQUAL_S(sizeof(set_cs), &set_cs, &get_cs)) {
            printf(" The get cpu set is not equal to set on id: %ld\n", i);
            return 1;
        }
    }

    /* test for multiple cpu affinity */
    CPU_ZERO(&set_cs);
    CPU_ZERO(&get_cs);
    CPU_SET(0, &set_cs);
    CPU_SET(1, &set_cs);
    ret = sched_setaffinity(0, sizeof(set_cs), &set_cs);
    if (ret < 0) {
        printf(" Failed to set multiple affinity for current thread, id: 0 & 1\n");
        return 1;
    }
    ret = sched_getaffinity(0, sizeof(get_cs), &get_cs);
    if (ret < 0) {
        printf(" Failed to get multiple affinity for current thread, id: 0 & 1\n");
        return 1;
    }
    if (!CPU_EQUAL_S(sizeof(set_cs), &set_cs, &get_cs)) {
        printf(" The get cpu set is not equal to set on id: 0 & 1\n");
        return 1;
    }

    printf("TEST OK: test completed successfully\n");
    return 0;
}
