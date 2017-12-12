/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* This Hello World simply print out "Hello World" */

#include "pal.h"
#include "pal_debug.h"

#define __NR_write 1

char str[] = "Hello World\n";

int main (int argc, char ** argv, char ** envp)
{
    pal_printf("start program: %s\n", pal_control.executable);

    asm volatile("syscall" :: "a"(__NR_write), "D"(1), "S"(str),
                 "d"(sizeof(str) - 1));

    return 0;
}
