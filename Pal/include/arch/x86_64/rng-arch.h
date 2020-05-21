#ifndef _X86_64_RNG_ARCH_H
#define _X86_64_RNG_ARCH_H

#include <immintrin.h>

/* get a 64 bit random number; compile with -mrdrnd */
static inline unsigned long long get_rand64(void) {
    unsigned long long rand64;
    while (__builtin_ia32_rdrand64_step(&rand64) == 0)
        /*nop*/;
    return rand64;
}

#endif /* _X86_64_RNG_ARCH_H */
