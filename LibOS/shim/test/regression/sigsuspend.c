/* Copyright 2019 Intel Corporation.
 * Copyright 2019 Isaku Yamahata <isaku.yamahata at intel com>
                                 <isaku.yamahata at gmail com>
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

#include <stdbool.h>

#include <err.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

volatile int sigcount = 0;

void handler(int sig)
{
    sigcount++;
}

int main(void)
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGALRM);

    int ret = sigprocmask(SIG_BLOCK, &mask, NULL);
    if (ret < 0)
        errx(ret, "sigprocmask");

    signal(SIGALRM, &handler);
    sigemptyset(&mask);
    int count = 0;
    while (true) {
        printf("count %d sigcount %d\n", count, sigcount);
        fflush(stdout);

        struct timespec t = {
            .tv_sec = 1,
            .tv_nsec = 0
        };
        alarm(1);
        nanosleep(&t, NULL);
        sigsuspend(&mask);
        count++;
    }
}
