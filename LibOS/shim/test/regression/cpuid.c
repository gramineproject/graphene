/* Sanity checks on values returned by CPUID. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void cpuid(uint32_t leaf, uint32_t subleaf, uint32_t vs[4]) {
    __asm__ volatile("cpuid" : "=a"(vs[0]), "=b"(vs[1]), "=c"(vs[2]), "=d"(vs[3])
                             : "0"(leaf), "2"(subleaf));
}

static void test_cpuid_leaf_0xd(void) {
    uint32_t vs[4] = {0, 0, 0, 0};

    const uint32_t leaf = 0xd;
    // Sub-leaf IDs for the various extensions.
    enum {
        AVX = 2, MPX_1, MPX_2, AVX512_1, AVX512_2, AVX512_3, PKRU = 9 };
    const uint32_t extension_sizes_bytes[] = {0, 0, 256, 64, 64, 64, 512, 1024, 0, 8};
    const uint32_t extension_unavailable = 0;

    cpuid(leaf, AVX, vs);
    if (!(vs[0] == extension_unavailable || vs[0] == extension_sizes_bytes[AVX]))
        abort();
    memset(vs, 0, sizeof(vs));

    cpuid(leaf, MPX_1, vs);
    if (!(vs[0] == extension_unavailable || vs[0] == extension_sizes_bytes[MPX_1]))
        abort();
    memset(vs, 0, sizeof(vs));

    cpuid(leaf, MPX_2, vs);
    if (!(vs[0] == extension_unavailable || vs[0] == extension_sizes_bytes[MPX_2]))
        abort();
    memset(vs, 0, sizeof(vs));

    cpuid(leaf, AVX512_1, vs);
    if (!(vs[0] == extension_unavailable || vs[0] == extension_sizes_bytes[AVX512_1]))
        abort();
    memset(vs, 0, sizeof(vs));

    cpuid(leaf, AVX512_2, vs);
    if (!(vs[0] == extension_unavailable || vs[0] == extension_sizes_bytes[AVX512_2]))
        abort();
    memset(vs, 0, sizeof(vs));

    cpuid(leaf, AVX512_3, vs);
    if (!(vs[0] == extension_unavailable || vs[0] == extension_sizes_bytes[AVX512_3]))
        abort();
    memset(vs, 0, sizeof(vs));

    cpuid(leaf, PKRU, vs);
    if (!(vs[0] == extension_unavailable || vs[0] == extension_sizes_bytes[PKRU]))
        abort();
    memset(vs, 0, sizeof(vs));
}

int main(int argc, char** argv, char** envp) {

    test_cpuid_leaf_0xd();
    printf("CPUID test passed.\n");
    return 0;
}
