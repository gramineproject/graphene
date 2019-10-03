#include "api.h"
#include "pal.h"
#include "pal_debug.h"

#define UNIT (pal_control.alloc_align)

static volatile int count = 0;

void handler(PAL_PTR event, PAL_NUM arg, PAL_CONTEXT* context) {
    count++;
    pal_printf("Memory Fault %d\n", count);

    while (*(unsigned char*)context->rip != 0x90) {
        context->rip++;
    }

    DkExceptionReturn(event);
}

int main(int argc, char** argv, char** envp) {
    volatile int c;
    DkSetExceptionHandler(handler, PAL_EVENT_MEMFAULT);

    void* mem1 = (void*)DkVirtualMemoryAlloc(NULL, UNIT * 4, 0, PAL_PROT_READ | PAL_PROT_WRITE);

    if (mem1)
        pal_printf("Memory Allocation OK\n");

    void* mem2 = (void*)DkVirtualMemoryAlloc(NULL, UNIT, 0, PAL_PROT_READ | PAL_PROT_WRITE);

    if (mem2) {
        c                    = count;
        *(volatile int*)mem2 = 0;
        pal_printf("(int *) %p = %d\n", mem2, *(volatile int*)mem2);
        if (c == count)
            pal_printf("Memory Allocation Protection (RW) OK\n");

        DkVirtualMemoryProtect(mem2, UNIT, PAL_PROT_READ);
        c                    = count;
        *(volatile int*)mem2 = 0;
        __asm__ volatile("nop");
        if (c == count - 1)
            pal_printf("Memory Protection (R) OK\n");

        DkVirtualMemoryFree(mem2, UNIT);
        c                    = count;
        *(volatile int*)mem2 = 0;
        __asm__ volatile("nop");
        if (c == count - 1)
            pal_printf("Memory Deallocation OK\n");
    }

    void* mem3 = (void*)pal_control.user_address.start;
    void* mem4 = (void*)pal_control.user_address.end - UNIT;

    if (mem3 >= pal_control.executable_range.start && mem3 < pal_control.executable_range.end)
        mem3 = (void*)ALIGN_UP_PTR(pal_control.executable_range.end, UNIT);

    mem3 = (void*)DkVirtualMemoryAlloc(mem3, UNIT, 0, PAL_PROT_READ | PAL_PROT_WRITE);
    mem4 = (void*)DkVirtualMemoryAlloc(mem4, UNIT, 0, PAL_PROT_READ | PAL_PROT_WRITE);

    if (mem3 && mem4)
        pal_printf("Memory Allocation with Address OK\n");

    /* Testing total memory */
    pal_printf("Total Memory: %lu\n", pal_control.mem_info.mem_total);

    /* Testing available memory (must be within valid range) */
    PAL_NUM avail = DkMemoryAvailableQuota();
    if (avail > 0 && avail < pal_control.mem_info.mem_total)
        pal_printf("Get Memory Available Quota OK\n");

    return 0;
}
