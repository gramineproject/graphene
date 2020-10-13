#include <stdint.h>

int main(void) {
#ifdef __amd64__
    volatile uint64_t val = 0;

    __asm__ volatile("int3");

    __asm__(
        "movq %1, %%rdx\n"
        "int3\n"
        "movq %%rdx, %0\n"
        : "=m"(val)
        : "m"(val)
        : "rdx");

    __asm__(
        "movhps %1, %%xmm0\n"
        "movlps %1, %%xmm0\n"
        "int3\n"
        "movlps %%xmm0, %0\n"
        : "=m"(val)
        : "m"(val)
        : "xmm0");
#endif
    return 0;
}
