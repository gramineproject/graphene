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
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sched.h>
#include <stdlib.h>

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

int main(int argc, const char** argv) {

    int i;
    long ret;
    cpu_set_t set_cs, get_cs;
    size_t cpucnt = sysconf(_SC_NPROCESSORS_ONLN);


    for (i = 0; i < cpucnt; i++) {
        printf("Testing processor id: %d\n", i);
        CPU_ZERO(&set_cs);
        CPU_ZERO(&get_cs);
        CPU_SET(i, &set_cs);
        ret = sched_setaffinity(0, sizeof(set_cs), &set_cs);
        if (ret < 0) {
            printf(" Failed to set affinity for current thread, id: %d\n", i);
            return ret;
        }
        ret = sched_getaffinity(0, sizeof(get_cs), &get_cs);
        if (ret < 0) {
            printf(" Failed to get affinity for current thread, id: %d\n", i);
            return ret;
        }
        if (!CPU_EQUAL_S(sizeof(set_cs), &set_cs, &get_cs)) {
            printf(" The get cpu set is not equal to set on id: %d\n", i);
            return -1;
        }
    }

    printf("test completed successfully\n");
    return 0;
}
