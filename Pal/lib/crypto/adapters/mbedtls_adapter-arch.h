#ifndef MBEDTLS_ADAPTER_ARCH_H
#define MBEDTLS_ADAPTER_ARCH_H

#if defined(__i386__) || defined(__x86_64__)

#include <immintrin.h>

static inline unsigned long long get_rand64(void) {
    unsigned long long rand64;
    while (__builtin_ia32_rdrand64_step(&rand64) == 0)
        /*nop*/;
    return rand64;
}

#else

#error Unsupported architecture

#endif

#endif /* MBEDTLS_ADAPTER_ARCH_H */
