/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* This Hello World demostrate a simple multithread program */
#include "pal.h"
#include "pal_debug.h"

void * private1 = "Hello World 1";
void * private2 = "Hello World 2";

static volatile int count1 = 0;

int callback1 (void * args)
{
    pal_printf("Run in Child Thread: %s\n", args);

    while (count1 < 10) {
        while (!(count1 % 2))
            DkThreadYieldExecution();
        count1++;
        asm volatile("nop" ::: "memory");
    }

    pal_printf("Threads Run in Parallel OK\n");

    DkSegmentRegister(PAL_SEGMENT_FS, &private2);
    const char * ptr2;
    asm volatile("mov %%fs:0, %0" : "=r"(ptr2) :: "memory");
    pal_printf("Private Message (FS Segment) 2: %s\n", ptr2);

    count1 = 100;
    asm volatile("nop" ::: "memory");
    DkThreadExit();
    count1 = 101;
    asm volatile("nop" ::: "memory");

    return 0;
}

int main (int argc, const char ** argv, const char ** envp)
{
    DkSegmentRegister(PAL_SEGMENT_FS, &private1);
    const char * ptr1;
    asm volatile("mov %%fs:0, %0" : "=r"(ptr1) :: "memory");
    pal_printf("Private Message (FS Segment) 1: %s\n", ptr1);

    PAL_HANDLE thread1 = DkThreadCreate(callback1, "Hello World", 0);

    if (thread1) {
        pal_printf("Child Thread Created\n");

        while (count1 < 10) {
            while (!!(count1 % 2))
                DkThreadYieldExecution();
            count1++;
            asm volatile("nop" ::: "memory");
        }

        while (count1 < 100)
            DkThreadYieldExecution();
        for (int i = 0 ; i < 300 ; i++)
            DkThreadYieldExecution();
        if (count1 == 100)
            pal_printf("Child Thread Exited\n");
    }

    return 0;
}

