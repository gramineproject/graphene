/* Copyright (C) 2020 Intel Corp.
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

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
