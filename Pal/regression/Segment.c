#include "pal.h"
#include "pal_debug.h"

void* dummy = &dummy;

int main(int argc, char** argv, char** envp) {
    DkSegmentRegister(PAL_SEGMENT_FS, dummy);
    void* ptr;
    __asm__ volatile("mov %%fs:0, %0" : "=r"(ptr)::"memory");
    pal_printf("TLS = %p\n", ptr);
    return 0;
}
