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
