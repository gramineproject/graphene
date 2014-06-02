/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

int main (int argc, char * const * argv, const char * const * envp)
{
    char fds[2] = { dup(1), 0 };
    int outfd = dup(1);

    if (argc > 1) {
        argv++;
    } else {
        char ** new_argv = malloc(sizeof(const char *) * 3);
        new_argv[0] = "./exec_victim";
        new_argv[1] = fds;
        new_argv[2] = NULL;
        argv = new_argv;
    }

    setenv("IN_EXECVE", "1", 1);

    int pid = fork();

    if (pid == 0) {
        close(outfd);
        execv(argv[0], argv);
    }

    wait(NULL);

    FILE * out = fdopen(outfd, "a");
    if (!out) {
        printf("cannot open file descriptor\n");
        return -1;
    }

    fprintf(out, "Goodbye world!\n");
    return 0;
}
