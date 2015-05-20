/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

int main(int argc, char ** argv)
{
    int times = 0, i;
    pid_t pid;

    if (argc > 1)
        times = atoi(argv[1]);

    for (i = 0 ; i < times ; i++) {
        pid = fork();

        if (pid < 0)
            exit(1);

        if (pid > 0) {
            waitpid(pid, NULL, 0);
            exit(0);
        }
    }

    sleep(1);
    return 0;
}
