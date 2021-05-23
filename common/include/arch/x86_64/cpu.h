/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef CPU_H
#define CPU_H

#include <stdint.h>
#include <stdnoreturn.h>

#define PAGE_SIZE       (1ul << 12)
#define PRESET_PAGESIZE PAGE_SIZE

enum CPUID_WORD {
    CPUID_WORD_EAX = 0,
    CPUID_WORD_EBX = 1,
    CPUID_WORD_ECX = 2,
    CPUID_WORD_EDX = 3,
    CPUID_WORD_NUM = 4,
};

#define INTEL_SGX_LEAF 0x12 /* Intel SGX Capabilities: CPUID Leaf 12H */

static inline void cpuid(unsigned int leaf, unsigned int subleaf, unsigned int words[]) {
    __asm__("cpuid"
            : "=a"(words[CPUID_WORD_EAX]),
              "=b"(words[CPUID_WORD_EBX]),
              "=c"(words[CPUID_WORD_ECX]),
              "=d"(words[CPUID_WORD_EDX])
            : "a"(leaf),
              "c"(subleaf));
}

static inline uint64_t get_tsc(void) {
    unsigned long lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return lo | ((uint64_t)hi << 32);
}

/*!
 * \brief Low-level wrapper around RDRAND instruction (get hardware-generated random value).
 */
static inline uint32_t rdrand(void) {
    uint32_t ret;
    __asm__ volatile(
        "1: .byte 0x0f, 0xc7, 0xf0\n" /* RDRAND %EAX */
        "jnc 1b\n"
        :"=a"(ret)
        :: "cc");
    return ret;
}

/*!
 * \brief Low-level wrapper around RDFSBASE instruction (read FS register; allowed in enclaves).
 */
static inline uint64_t rdfsbase(void) {
    uint64_t fsbase;
    __asm__ volatile(
        ".byte 0xf3, 0x48, 0x0f, 0xae, 0xc0\n" /* RDFSBASE %RAX */
        : "=a"(fsbase) :: "memory");
    return fsbase;
}

/*!
 * \brief Low-level wrapper around WRFSBASE instruction (modify FS register; allowed in enclaves).
 */
static inline void wrfsbase(uint64_t addr) {
    __asm__ volatile(
        ".byte 0xf3, 0x48, 0x0f, 0xae, 0xd7\n" /* WRFSBASE %RDI */
        :: "D"(addr) : "memory");
}

static inline noreturn void die_or_inf_loop(void) {
    __asm__ volatile (
        "1: \n"
        "ud2 \n"
        "jmp 1b \n"
    );
    __builtin_unreachable();
}

#define CPU_RELAX() __asm__ volatile("pause")

/* some non-Intel clones support out of order store; WMB() ceases to be a nop for these */
#define MB()  __asm__ __volatile__("mfence" ::: "memory")
#define RMB() __asm__ __volatile__("lfence" ::: "memory")
#define WMB() __asm__ __volatile__("sfence" ::: "memory")

#endif /* CPU_H */
