/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

void handler (int signal)
{
    printf("get signal: %d\n", signal);
    exit(0);
}

int main (void)
{
    int i = 0;
    signal(SIGFPE, &handler);
    i =  1 / i;
    return 0;
}
