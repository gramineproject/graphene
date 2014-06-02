/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <stdio.h>
#include <unistd.h>

int main(int argc, char ** argv)
{
    dup2(1, 255);
    close(1);
    FILE * new_stdout = fdopen(255, "a");
    fprintf(new_stdout, "Hello World!\n");
    fflush(new_stdout);
    return 0;
}
