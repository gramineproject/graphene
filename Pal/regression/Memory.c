/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include "pal.h"
#include "pal_debug.h"
#include "api.h"

#define UNIT pal_control.alloc_align

static volatile int count = 0;

void handler (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    count++;
    pal_printf("Memory Fault %d\n", count);

    while (*(unsigned char *) context->rip != 0x90)
        context->rip++;

    DkExceptionReturn(event);
}

int main (int argc, char ** argv, char ** envp)
{
    volatile int c;
    DkSetExceptionHandler(handler, PAL_EVENT_MEMFAULT, 0);

    void * mem1 = (void *) DkVirtualMemoryAlloc(NULL, UNIT * 4, 0,
                                                PAL_PROT_READ|PAL_PROT_WRITE);

    if (mem1)
        pal_printf("Memory Allocation OK\n");

    void * mem2 = (void *) DkVirtualMemoryAlloc(NULL, UNIT, 0,
                                                PAL_PROT_READ|PAL_PROT_WRITE);

    if (mem2) {
        c = count;
        *(volatile int *) mem2 = 0;
        pal_printf("(int *) %p = %d\n", mem2, *(volatile int *) mem2);
        if (c == count)
            pal_printf("Memory Allocation Protection (RW) OK\n");

        DkVirtualMemoryProtect(mem2, UNIT, PAL_PROT_READ);
        c = count;
        *(volatile int *) mem2 = 0;
        asm volatile("nop");
        if (c == count - 1)
            pal_printf("Memory Protection (R) OK\n");

        DkVirtualMemoryFree(mem2, UNIT);
        c = count;
        *(volatile int *) mem2 = 0;
        asm volatile("nop");
        if (c == count - 1)
            pal_printf("Memory Deallocation OK\n");
    }

    void * mem3 = (void *) DkVirtualMemoryAlloc(pal_control.user_address.start,
                                                UNIT, 0,
                                                PAL_PROT_READ|PAL_PROT_WRITE);
    void * mem4 = (void *) DkVirtualMemoryAlloc(pal_control.user_address.end - UNIT,
                                                UNIT, 0,
                                                PAL_PROT_READ|PAL_PROT_WRITE);


    if (mem3 && mem4)
        pal_printf("Memory Allocation with Address OK\n");

    /* total memory */
    pal_printf("Total Memory: %llu\n", pal_control.mem_info.mem_total);

    unsigned long before = DkMemoryAvailableQuota();
    void * mem5 = (void *) DkVirtualMemoryAlloc(NULL, UNIT * 1000, 0,
                                                PAL_PROT_READ|PAL_PROT_WRITE);

    if (mem5) {
        unsigned long after = before;

        for (int i = 0 ; i < 10000 ; i++) {
            for (void * ptr = mem5 ; ptr < mem5 + UNIT * 1000 ; ptr += UNIT)
                *(volatile int *) ptr = 0;

            unsigned long quota = DkMemoryAvailableQuota();
            if (quota < after)
                after = quota;
        }

        pal_printf("Memory Qouta Before Allocation: %ld\n", before);
        pal_printf("Memory Qouta After  Allocation: %ld\n", after);

        /* chance are some pages are evicted, so at least 80% accuracy */
        if (before >= after + UNIT * 800)
            pal_printf("Get Memory Available Quota OK\n");
    }

    return 0;
}
