/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

int main (int argc, const char ** argv, const char ** envp)
{
    char * const new_argv[] = { "DUMMY", NULL };

    /* passing NULL to execv/execve must return -1 */
    int r = execv(NULL, new_argv);
    if (r == -1)
        printf("execv correctly returned error\n");

    return 0;
}
