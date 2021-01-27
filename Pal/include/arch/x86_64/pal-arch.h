/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains definition of x86_64-specific aspects of PAL.
 */

#ifndef PAL_H
// TODO: fix this
#error This header is usable only inside pal.h (due to a cyclic dependency).
#endif

#ifndef PAL_ARCH_H
#define PAL_ARCH_H

#include <assert.h>
#include <stdint.h>

#include "cpu.h"
#include "pal.h"

typedef struct pal_tcb PAL_TCB;

#define PAL_LIBOS_TCB_SIZE 256


#define STACK_PROTECTOR_CANARY_DEFAULT  0xbadbadbadbadUL

/* Used to represent plain integers (only numeric values) */
#define PAL_SYSFS_INT_FILESZ 16
/* Used to represent buffers having numeric values with text. E.g "1024576K" */
#define PAL_SYSFS_BUF_FILESZ 64
/* Used to represent cpumaps like "00000000,ffffffff,00000000,ffffffff" */
#define PAL_SYSFS_MAP_FILESZ 256

typedef struct pal_tcb {
    struct pal_tcb* self;
    /* random per-thread canary used by GCC's stack protector; must be at %gs:[0x8]
     * because we specify `-mstack-protector-guard-reg=%gs -mstack-protector-guard-offset=8` */
    uint64_t stack_protector_canary;
    /* uint64_t for alignment */
    uint64_t libos_tcb[(PAL_LIBOS_TCB_SIZE + sizeof(uint64_t) - 1) / sizeof(uint64_t)];
    /* data private to PAL implementation follows this struct. */
} PAL_TCB;

__attribute__((__optimize__("-fno-stack-protector")))
static inline void pal_tcb_arch_set_stack_canary(PAL_TCB* tcb, uint64_t canary) {
    tcb->stack_protector_canary = canary;
}

static_assert(offsetof(PAL_TCB, stack_protector_canary) == 0x8,
              "unexpected offset of stack_protector_canary in PAL_TCB struct");

#include "pal_host-arch.h"

static inline PAL_TCB* pal_get_tcb(void) {
    PAL_TCB* tcb;
    __asm__("movq %%gs:%c1, %0" : "=r"(tcb) : "i"(offsetof(struct pal_tcb, self)) : "memory");
    return tcb;
}

static inline unsigned long count_ulong_bits_set(unsigned long x) {
    unsigned long result;
    __asm__("popcnt %1, %0" : "=r"(result) : "r"(x) : "cc");
    return result;
}

union pal_csgsfs {
    struct {
        uint16_t cs;
        uint16_t gs;
        uint16_t fs;
        uint16_t ss;
    };
    uint64_t csgsfs;
};

/* Adopt Linux style fp layout, _libc_fpstate of glibc:
 * Because self-contained definition is needed for Pal definition,
 * same layout is defined with PAL prefix.
 */
#define PAL_FP_XSTATE_MAGIC1      0x46505853U
#define PAL_FP_XSTATE_MAGIC2      0x46505845U
#define PAL_FP_XSTATE_MAGIC2_SIZE (sizeof(PAL_FP_XSTATE_MAGIC2))

enum PAL_XFEATURE {
    PAL_XFEATURE_FP,
    PAL_XFEATURE_SSE,
    PAL_XFEATURE_YMM,
    PAL_XFEATURE_BNDREGS,
    PAL_XFEATURE_BNDCSR,
    PAL_XFEATURE_OPMASK,
    PAL_XFEATURE_ZMM_Hi256,
    PAL_XFEATURE_Hi16_ZMM,
    PAL_XFEATURE_PT,
    PAL_XFEATURE_PKRU,

    PAL_XFEATURE_MAX,
};

#define PAL_XFEATURE_MASK_FP        (1UL << PAL_XFEATURE_FP)
#define PAL_XFEATURE_MASK_SSE       (1UL << PAL_XFEATURE_SSE)
#define PAL_XFEATURE_MASK_YMM       (1UL << PAL_XFEATURE_YMM)
#define PAL_XFEATURE_MASK_BNDREGS   (1UL << PAL_XFEATURE_BNDREGS)
#define PAL_XFEATURE_MASK_BNDCSR    (1UL << PAL_XFEATURE_BNDCSR)
#define PAL_XFEATURE_MASK_OPMASK    (1UL << PAL_XFEATURE_OPMASK)
#define PAL_XFEATURE_MASK_ZMM_Hi256 (1UL << PAL_XFEATURE_ZMM_Hi256)
#define PAL_XFEATURE_MASK_Hi16_ZMM  (1UL << PAL_XFEATURE_Hi16_ZMM)
#define PAL_XFEATURE_MASK_PT        (1UL << PAL_XFEATURE_PT)
#define PAL_XFEATURE_MASK_PKRU      (1UL << PAL_XFEATURE_PKRU)

#define PAL_XFEATURE_MASK_FPSSE     (PAL_XFEATURE_MASK_FP \
                                     | PAL_XFEATURE_MASK_SSE)
#define PAL_XFEATURE_MASK_AVX512    (PAL_XFEATURE_MASK_OPMASK \
                                     | PAL_XFEATURE_MASK_ZMM_Hi256 \
                                     | PAL_XFEATURE_MASK_Hi16_ZMM)

typedef struct {
    uint32_t magic1;        /*!< PAL_FP_XSTATE_MAGIC1 */
    uint32_t extended_size; /*!< g_xsave_size */
    uint64_t xfeatures;     /*!< XSAVE feature */
    uint32_t xstate_size;   /*!< g_xsave_size + PAL_FP_STATE_MAGIC2_SIZE */
    uint32_t padding[7];
} PAL_FPX_SW_BYTES;

typedef struct {
    uint32_t cwd;
    uint32_t swd;
    uint32_t twd;
    uint32_t fip;
    uint32_t fcs;
    uint32_t foo;
    uint32_t fos;
    uint32_t st_space[20];
    uint8_t ftop;
    uint8_t changed;
    uint8_t lookahead;
    uint8_t no_update;
    uint8_t rm;
    uint8_t alimit;
    void* info; /* struct math_emu_info */
    uint32_t entry_eip;
} PAL_SWREGS_STATE;

typedef struct {
    uint16_t significand[4];
    uint16_t exponent;
    uint16_t padding[3];
} PAL_FPXREG;

typedef struct {
    uint32_t element[4];
} PAL_XMMREG;

typedef struct {
    /* 64-bit FXSAVE format.  */
    uint16_t cwd;
    uint16_t swd;
    uint16_t ftw;
    uint16_t fop;
    uint64_t rip;
    uint64_t rdp;
    uint32_t mxcsr;
    uint32_t mxcr_mask;
    PAL_FPXREG st[8];
    PAL_XMMREG xmm[16];
    union {
        uint32_t padding[24];
        struct {
            uint32_t padding2[12];
            PAL_FPX_SW_BYTES sw_reserved;
        };
    };
} PAL_FPSTATE;

typedef struct {
    uint64_t xfeatures;
    uint64_t xcomp_bv;
    uint64_t reserved[6];
} __attribute__((packed)) PAL_XSTATE_HEADER;

#define PAL_XSTATE_ALIGN 64

typedef struct {
    PAL_FPSTATE fpstate;
    PAL_XSTATE_HEADER header;
} __attribute__((packed, aligned(PAL_XSTATE_ALIGN))) PAL_XREGS_STATE;

/* Define PAL_CONTEXT_ outside the typedef for Doxygen */
struct PAL_CONTEXT_ {
    PAL_NUM r8, r9, r10, r11, r12, r13, r14, r15;
    PAL_NUM rdi, rsi, rbp, rbx, rdx, rax, rcx;
    PAL_NUM rsp, rip;
    PAL_NUM efl, csgsfs, err, trapno, oldmask, cr2;
    PAL_XREGS_STATE* fpregs;
};
typedef struct PAL_CONTEXT_ PAL_CONTEXT;

static inline void pal_context_set_ip(PAL_CONTEXT* context, PAL_NUM insnptr) {
    context->rip = insnptr;
}

static inline PAL_NUM pal_context_get_ip(PAL_CONTEXT* context) {
    return context->rip;
}

static inline bool pal_context_has_user_pagefault(PAL_CONTEXT* context) {
    return !!(context->err & 4);
}

enum {
    HUGEPAGES_2M = 0,
    HUGEPAGES_1G,
    HUGEPAGES_MAX,
};

/* PAL_CPU_INFO holds /proc/cpuinfo data */
typedef struct PAL_CPU_INFO_ {
    /* Number of logical cores available in the host */
    PAL_NUM online_logical_cores;
    /* Max number of logical cores available in the host */
    PAL_NUM possible_logical_cores;
    /* Number of physical cores in a socket (physical package) */
    PAL_NUM physical_cores_per_socket;
    /* array of "logical core -> socket" mappings; has online_logical_cores elements */
    int* cpu_socket;
    PAL_STR cpu_vendor;
    PAL_STR cpu_brand;
    PAL_NUM cpu_family;
    PAL_NUM cpu_model;
    PAL_NUM cpu_stepping;
    double  cpu_bogomips;
    PAL_STR cpu_flags;
} PAL_CPU_INFO;

typedef struct PAL_CORE_CACHE_INFO_ {
    char shared_cpu_map[PAL_SYSFS_MAP_FILESZ];
    char level[PAL_SYSFS_INT_FILESZ];
    char type[PAL_SYSFS_BUF_FILESZ];
    char size[PAL_SYSFS_BUF_FILESZ];
    char coherency_line_size[PAL_SYSFS_INT_FILESZ];
    char number_of_sets[PAL_SYSFS_INT_FILESZ];
    char physical_line_partition[PAL_SYSFS_INT_FILESZ];
} PAL_CORE_CACHE_INFO;

typedef struct PAL_CORE_TOPO_INFO_ {
    /* [0] element is uninitialized because core 0 is always online */
    char is_logical_core_online[PAL_SYSFS_INT_FILESZ];
    char core_id[PAL_SYSFS_INT_FILESZ];
    char core_siblings[PAL_SYSFS_MAP_FILESZ];
    char thread_siblings[PAL_SYSFS_MAP_FILESZ];
    PAL_CORE_CACHE_INFO* cache; /* Array of size num_cache_index, owned by this struct */
} PAL_CORE_TOPO_INFO;

typedef struct PAL_NUMA_HUGEPAGE_INFO_ {
    char nr_hugepages[PAL_SYSFS_INT_FILESZ];
} PAL_NUMA_HUGEPAGE_INFO;

typedef struct PAL_NUMA_TOPO_INFO_ {
    char cpumap[PAL_SYSFS_MAP_FILESZ];
    char distance[PAL_SYSFS_INT_FILESZ];
    PAL_NUMA_HUGEPAGE_INFO hugepages[HUGEPAGES_MAX];
} PAL_NUMA_TOPO_INFO;

/* This struct takes ~1.6KB. On a single socket, 4 logical core system, with 3 cache levels
 * it would take ~8KB in memory. */
typedef struct PAL_TOPO_INFO_ {
    char online_logical_cores[PAL_SYSFS_BUF_FILESZ];
    char possible_logical_cores[PAL_SYSFS_BUF_FILESZ];
    char online_nodes[PAL_SYSFS_BUF_FILESZ];
    /* Number of nodes available in the host */
    PAL_NUM num_online_nodes;
    /* cache index corresponds to number of cache levels (such as L2 or L3) available on the host */
    PAL_NUM num_cache_index;
    PAL_CORE_TOPO_INFO* core_topology; /* Array of logical core topology info, owned by this struct */
    PAL_NUMA_TOPO_INFO* numa_topology; /* Array of numa topology info, owned by this struct */
} PAL_TOPO_INFO;

#endif /* PAL_ARCH_H */
