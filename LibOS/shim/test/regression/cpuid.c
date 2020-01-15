/* Sanity checks on values returned by CPUID. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct regs {
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
} __attribute__((packed));

static void cpuid(uint32_t leaf, uint32_t subleaf, struct regs* r) {
    __asm__ volatile("cpuid" : "=a"(r->eax), "=b"(r->ebx), "=c"(r->ecx), "=d"(r->edx)
                             : "0"(leaf), "2"(subleaf));
}

static void test_cpuid_leaf_0xd(void) {
    struct regs r = {0, };

    const uint32_t leaf = 0xd;
    // Sub-leaf IDs for the various extensions.
    enum cpu_extension {
        x87 = 0, SSE, AVX, MPX_1, MPX_2, AVX512_1, AVX512_2, AVX512_3, PKRU = 9 };
    const uint32_t extension_sizes_bytes[] =
        { [AVX] = 256, [MPX_1] = 64, [MPX_2] = 64, [AVX512_1] = 64, [AVX512_2] = 512,
          [AVX512_3] = 1024, [PKRU] = 8};
    enum register_index {
        EAX = 0, EBX, ECX, EDX
    };
    const uint32_t extension_unavailable = 0;

    cpuid(leaf, AVX, &r);
    if (!(r.eax == extension_unavailable || r.eax == extension_sizes_bytes[AVX]))
        abort();
    memset(&r, 0, sizeof(r));

    cpuid(leaf, MPX_1, &r);
    if (!(r.eax == extension_unavailable || r.eax == extension_sizes_bytes[MPX_1]))
        abort();
    memset(&r, 0, sizeof(r));

    cpuid(leaf, MPX_2, &r);
    if (!(r.eax == extension_unavailable || r.eax == extension_sizes_bytes[MPX_2]))
        abort();
    memset(&r, 0, sizeof(r));

    cpuid(leaf, AVX512_1, &r);
    if (!(r.eax == extension_unavailable || r.eax == extension_sizes_bytes[AVX512_1]))
        abort();
    memset(&r, 0, sizeof(r));

    cpuid(leaf, AVX512_2, &r);
    if (!(r.eax == extension_unavailable || r.eax == extension_sizes_bytes[AVX512_2]))
        abort();
    memset(&r, 0, sizeof(r));

    cpuid(leaf, AVX512_3, &r);
    if (!(r.eax == extension_unavailable || r.eax == extension_sizes_bytes[AVX512_3]))
        abort();
    memset(&r, 0, sizeof(r));

    cpuid(leaf, PKRU, &r);
    if (!(r.eax == extension_unavailable || r.eax == extension_sizes_bytes[PKRU]))
        abort();
    memset(&r, 0, sizeof(r));
}

int main(int argc, char** argv, char** envp) {

    test_cpuid_leaf_0xd();
    printf("CPUID test passed.\n");
    return 0;
}
