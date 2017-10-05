/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* This Hello World simply print out "Hello World" */

#include "pal.h"
#include "pal_debug.h"

#define __NR_write 1

char str[13];

int main (int argc, char ** argv, char ** envp)
{
    pal_printf("start program: %s\n", pal_control.executable);

    str[0] = 'H';
    str[1] = 'e';
    str[2] = 'l';
    str[3] = 'l';
    str[4] = 'o';
    str[5] = ' ';
    str[6] = 'W';
    str[7] = 'o';
    str[8] = 'r';
    str[9] = 'l';
    str[10] = 'd';
    str[11] = '\n';
    str[12] = 0;

    asm volatile("syscall" :: "a"(__NR_write), "D"(1), "S"(str), "d"(12));

    return 0;
}
