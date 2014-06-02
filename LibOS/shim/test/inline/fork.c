/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <shim_table.h>
#include <errno.h>

void main (int argc, char ** argv)
{
    pid_t pid = shim_fork();

    if (pid < 0) {
        shim_write(1, "failed on fork\n", 15);
        shim_exit_group(-1);
    }

    if (pid == 0) {
        shim_write(1, "Hello, Dad!\n", 12);
    }
    else {
        shim_write(1, "Hello, Kid!\n", 12);
    }

    shim_exit_group(0);
}
