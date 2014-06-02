/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

void handler (int signal)
{
    printf("alarm goes off\n");
}

int main(int argc, char ** argv)
{
    signal(SIGALRM, &handler);
    alarm(1);
    sleep(3);
    return 0;
}
