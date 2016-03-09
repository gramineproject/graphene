/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* This Hello World simply print out "Hello World" */

#include "pal.h"
#include "pal_debug.h"

int main (int argc, char ** argv, char ** envp)
{
    PAL_NUM values[4];
    asm volatile("mov $0, %%rax\n"
                 "cpuid\n"
                 : "=a"(values[0]),
                   "=b"(values[1]),
                   "=c"(values[2]),
                   "=d"(values[3])
                :: "memory");

    pal_printf("cpuid[0] = %08x %08x %08x %08x\n", values[0], values[1],
               values[2], values[3]);

    return 0;
}
