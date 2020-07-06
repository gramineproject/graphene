/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * db_main-x86_64.c
 *
 * This file contains x86_64-specific functions of the PAL loader.
 */

#include "api.h"
#include "bogomips.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_security.h"

#define FOUR_CHARS_VALUE(s, w)      \
    (s)[0] = (w) & 0xff;            \
    (s)[1] = ((w) >>  8) & 0xff;    \
    (s)[2] = ((w) >> 16) & 0xff;    \
    (s)[3] = ((w) >> 24) & 0xff;

#define BPI  32
#define POWER2(power) \
    (1ULL << (power))
#define RIGHTMASK(width) \
    (((unsigned long)(width) >= BPI) ? ~0ULL : POWER2(width) - 1ULL)

#define BIT_EXTRACT_LE(value, start, after) \
    (((unsigned long)(value) & RIGHTMASK(after)) >> start)

static char* cpu_flags[] = {
    "fpu",    // "x87 FPU on chip"
    "vme",    // "virtual-8086 mode enhancement"
    "de",     // "debugging extensions"
    "pse",    // "page size extensions"
    "tsc",    // "time stamp counter"
    "msr",    // "RDMSR and WRMSR support"
    "pae",    // "physical address extensions"
    "mce",    // "machine check exception"
    "cx8",    // "CMPXCHG8B inst."
    "apic",   // "APIC on chip"
    NULL,
    "sep",    // "SYSENTER and SYSEXIT"
    "mtrr",   // "memory type range registers"
    "pge",    // "PTE global bit"
    "mca",    // "machine check architecture"
    "cmov",   // "conditional move/compare instruction"
    "pat",    // "page attribute table"
    "pse36",  // "page size extension"
    "pn",     // "processor serial number"
    "clflush",    // "CLFLUSH instruction"
    NULL,
    "dts",    // "debug store"
    "acpi",   // "Onboard thermal control"
    "mmx",    // "MMX Technology"
    "fxsr",   // "FXSAVE/FXRSTOR"
    "sse",    // "SSE extensions"
    "sse2",   // "SSE2 extensions"
    "ss",     // "self snoop"
    "ht",     // "hyper-threading / multi-core supported"
    "tm",     // "therm. monitor"
    "ia64",   // "IA64"
    "pbe",    // "pending break event"
};

static ssize_t read_file_buffer(const char* filename, char* buf, size_t buf_size) {
    int fd;

    fd = ocall_open(filename, O_RDONLY, 0);
    if (fd < 0)
        return fd;

    /* Although the whole file might not fit in this size, the first cpu description should. */
    ssize_t n = ocall_read(fd, buf, buf_size);
    ocall_close(fd);

    return n;
}

static double get_bogomips(void) {
    char buf[2048];
    ssize_t len;

    len = read_file_buffer("/proc/cpuinfo", buf, sizeof(buf) - 1);
    if (len < 0)
        return 0.0;
    buf[len] = 0;

    return sanitize_bogomips_value(get_bogomips_from_cpuinfo_buf(buf));
}

int _DkGetCPUInfo (PAL_CPU_INFO* ci) {
    unsigned int words[PAL_CPUID_WORD_NUM];
    int rv = 0;

    const size_t VENDOR_ID_SIZE = 13;
    char* vendor_id = malloc(VENDOR_ID_SIZE);
    _DkCpuIdRetrieve(0, 0, words);

    FOUR_CHARS_VALUE(&vendor_id[0], words[PAL_CPUID_WORD_EBX]);
    FOUR_CHARS_VALUE(&vendor_id[4], words[PAL_CPUID_WORD_EDX]);
    FOUR_CHARS_VALUE(&vendor_id[8], words[PAL_CPUID_WORD_ECX]);
    vendor_id[VENDOR_ID_SIZE - 1] = '\0';
    ci->cpu_vendor = vendor_id;
    // Must be an Intel CPU
    if (memcmp(vendor_id, "GenuineIntel", 12)) {
      free(vendor_id);
      return -PAL_ERROR_INVAL;
    }

    const size_t BRAND_SIZE = 49;
    char* brand = malloc(BRAND_SIZE);
    _DkCpuIdRetrieve(0x80000002, 0, words);
    memcpy(&brand[ 0], words, sizeof(unsigned int) * PAL_CPUID_WORD_NUM);
    _DkCpuIdRetrieve(0x80000003, 0, words);
    memcpy(&brand[16], words, sizeof(unsigned int) * PAL_CPUID_WORD_NUM);
    _DkCpuIdRetrieve(0x80000004, 0, words);
    memcpy(&brand[32], words, sizeof(unsigned int) * PAL_CPUID_WORD_NUM);
    brand[BRAND_SIZE - 1] = '\0';
    ci->cpu_brand = brand;

    /* we cannot use CPUID(0xb) because it counts even disabled-by-BIOS cores (e.g. HT cores);
     * instead, this is passed in via g_pal_sec at start-up time. */
    ci->cpu_num = g_pal_sec.num_cpus;

    _DkCpuIdRetrieve(1, 0, words);
    ci->cpu_family   = BIT_EXTRACT_LE(words[PAL_CPUID_WORD_EAX],  8, 12) +
                       BIT_EXTRACT_LE(words[PAL_CPUID_WORD_EAX], 20, 28);
    ci->cpu_model    = BIT_EXTRACT_LE(words[PAL_CPUID_WORD_EAX],  4,  8) +
                      (BIT_EXTRACT_LE(words[PAL_CPUID_WORD_EAX], 16, 20) << 4);
    ci->cpu_stepping = BIT_EXTRACT_LE(words[PAL_CPUID_WORD_EAX],  0,  4);

    int flen = 0, fmax = 80;
    char* flags = malloc(fmax);

    for (int i = 0 ; i < 32 ; i++) {
        if (!cpu_flags[i])
            continue;

        if (BIT_EXTRACT_LE(words[PAL_CPUID_WORD_EDX], i, i + 1)) {
            int len = strlen(cpu_flags[i]);
            if (flen + len + 1 > fmax) {
                char* new_flags = malloc(fmax * 2);
                memcpy(new_flags, flags, flen);
                free(flags);
                fmax *= 2;
                flags = new_flags;
            }
            memcpy(flags + flen, cpu_flags[i], len);
            flen += len;
            flags[flen++] = ' ';
        }
    }

    flags[flen ? flen - 1 : 0] = 0;
    ci->cpu_flags = flags;

    ci->cpu_bogomips = get_bogomips();
    if (ci->cpu_bogomips == 0.0) {
        SGX_DBG(DBG_E, "Warning: bogomips could not be retrieved, passing 0.0 to the application\n");
    }

    return rv;
}

size_t _DkRandomBitsRead(void* buffer, size_t size) {
    uint32_t rand;
    for (size_t i = 0; i < size; i += sizeof(rand)) {
        rand = rdrand();
        memcpy(buffer + i, &rand, MIN(sizeof(rand), size - i));
    }
    return 0;
}

int _DkSegmentRegisterSet(int reg, const void* addr) {
    /* GS is internally used, denied any access to it */
    if (reg != PAL_SEGMENT_FS)
        return -PAL_ERROR_DENIED;

    SET_ENCLAVE_TLS(fsbase, (void*)addr);
    wrfsbase((uint64_t)addr);
    return 0;
}

int _DkSegmentRegisterGet(int reg, void** addr) {
    /* GS is internally used, denied any access to it */
    if (reg != PAL_SEGMENT_FS)
        return -PAL_ERROR_DENIED;

    *addr = (void*)GET_ENCLAVE_TLS(fsbase);
    return 0;
}
