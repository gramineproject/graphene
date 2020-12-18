#include "pal.h"
#include "pal_debug.h"

void* dummy = &dummy;

int main(int argc, char** argv, char** envp) {
    if (!DkSegmentRegisterSet(PAL_SEGMENT_FS, dummy)) {
        pal_printf("Error setting FS\n");
        return 1;
    }

    void** ptr;
    __asm__ volatile("mov %%fs:0, %0" : "=r"(ptr)::"memory");

    if (ptr != &dummy) {
        pal_printf("Wrong FS set: %p\n", ptr);
        return 1;
    }

    pal_printf("Test OK\n");
    return 0;
}
