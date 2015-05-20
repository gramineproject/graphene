/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* This Hello World simply print out "Hello World" */

#include "pal.h"
#include "pal_debug.h"

void * private = &private;

int main (int argc, char ** argv, char ** envp)
{
    DkSegmentRegister(PAL_SEGMENT_FS, private);
    void * ptr;
    asm volatile("mov %%fs:0, %0" : "=r"(ptr) :: "memory");
    pal_printf("TLS = %p\n", ptr);
    return 0;
}
