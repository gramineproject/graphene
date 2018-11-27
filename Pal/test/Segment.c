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
