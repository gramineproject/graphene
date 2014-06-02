/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main (int argc, const char ** argv, const char ** envp)
{
    char fds[2] = { dup(1), 0 };
    int outfd = dup(1);
    char * new_argv[] = { "./exec_victim", fds, NULL };
    setenv("IN_EXECVE", "1", 1);
    execv(new_argv[0], new_argv);
    return 0;
}
