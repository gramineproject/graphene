/* This Hello World simply print out "Hello World" */

#include <stdint.h>

#include "pal.h"
#include "pal_debug.h"

int main(int argc, char** argv, char** envp) {
    void* p1 = (void*)DkVirtualMemoryAlloc(NULL, pal_control.alloc_align * 4, 0,
                                           PAL_PROT_READ | PAL_PROT_WRITE);

    void* p2 = (void*)DkVirtualMemoryAlloc(NULL, pal_control.alloc_align * 4, 0,
                                           PAL_PROT_READ | PAL_PROT_WRITE);

    void* p3 = (void*)DkVirtualMemoryAlloc(NULL, pal_control.alloc_align * 2, 0,
                                           PAL_PROT_READ | PAL_PROT_WRITE);

    DkVirtualMemoryAlloc((void*)(((uint64_t)p1 + (uint64_t)p2) / 2), pal_control.alloc_align * 4, 0,
                         PAL_PROT_READ | PAL_PROT_WRITE);

    DkVirtualMemoryAlloc(p3, pal_control.alloc_align * 2, 0, PAL_PROT_READ | PAL_PROT_WRITE);

    DkVirtualMemoryFree(p3, pal_control.alloc_align);

    return 0;
}
