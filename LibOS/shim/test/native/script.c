/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

int main (int argc, const char ** argv, const char ** envp)
{
    int newfd = dup(1), outfd = dup(1);
    char fd_argv[4];
    snprintf(fd_argv, 4, "%d", newfd);
    char * const new_argv[] = { "./script1.sh", fd_argv, NULL };

    setenv("IN_EXECVE", "1", 1);

    execv(new_argv[0], new_argv);
    return 0;
}
