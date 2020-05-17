/* Copyright (C) 2014 Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*!
 * \file pal-arch.h
 *
 * This file contains definition of x86_64-specific aspects of PAL.
 */

#ifndef PAL_ARCH_H
#define PAL_ARCH_H

#include <stdint.h>

#define PAGE_SIZE       (1 << 12)
#define PRESET_PAGESIZE PAGE_SIZE

typedef struct pal_tcb PAL_TCB;

#define PAL_LIBOS_TCB_SIZE 256

typedef struct pal_tcb {
    struct pal_tcb* self;
    /* uint64_t for alignment */
    uint64_t libos_tcb[(PAL_LIBOS_TCB_SIZE + sizeof(uint64_t) - 1) / sizeof(uint64_t)];
    /* data private to PAL implementation follows this struct. */
} PAL_TCB;

#include "pal_host-arch.h"

static inline PAL_TCB * pal_get_tcb (void)
{
    PAL_TCB * tcb;
    __asm__ ("movq %%gs:%c1,%q0"
             : "=r" (tcb)
             : "i" (offsetof(struct pal_tcb, self)));
    return tcb;
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
#define PAL_FP_XSTATE_MAGIC1        0x46505853U
#define PAL_FP_XSTATE_MAGIC2        0x46505845U
#define PAL_FP_XSTATE_MAGIC2_SIZE   (sizeof(PAL_FP_XSTATE_MAGIC2))

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

#define PAL_XFEATURE_MASK_FP                (1UL << PAL_XFEATURE_FP)
#define PAL_XFEATURE_MASK_SSE               (1UL << PAL_XFEATURE_SSE)
#define PAL_XFEATURE_MASK_YMM               (1UL << PAL_XFEATURE_YMM)
#define PAL_XFEATURE_MASK_BNDREGS           (1UL << PAL_XFEATURE_BNDREGS)
#define PAL_XFEATURE_MASK_BNDCSR            (1UL << PAL_XFEATURE_BNDCSR)
#define PAL_XFEATURE_MASK_OPMASK            (1UL << PAL_XFEATURE_OPMASK)
#define PAL_XFEATURE_MASK_ZMM_Hi256         (1UL << PAL_XFEATURE_ZMM_Hi256)
#define PAL_XFEATURE_MASK_Hi16_ZMM          (1UL << PAL_XFEATURE_Hi16_ZMM)
#define PAL_XFEATURE_MASK_PT                (1UL << PAL_XFEATURE_PT)
#define PAL_XFEATURE_MASK_PKRU              (1UL << PAL_XFEATURE_PKRU)

#define PAL_XFEATURE_MASK_FPSSE             (PAL_XFEATURE_MASK_FP \
                                             | PAL_XFEATURE_MASK_SSE)
#define PAL_XFEATURE_MASK_AVX512            (PAL_XFEATURE_MASK_OPMASK \
                                             | PAL_XFEATURE_MASK_ZMM_Hi256 \
                                             | PAL_XFEATURE_MASK_Hi16_ZMM)

typedef struct {
    uint32_t magic1;        /*!< PAL_FP_XSTATE_MAGIC1 */
    uint32_t extended_size; /*!< xsave_size */
    uint64_t xfeatures;     /*!< XSAVE feature */
    uint32_t xstate_size;   /*!< xsave_size + PAL_FP_STATE_MAGIC2_SIZE */
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

#define DEFAULT_OBJECT_EXEC_ADDR ((void*)0x555555554000) /* Linux base location for PIE binaries */

static inline void pal_context_set_ip(PAL_CONTEXT* context, PAL_NUM insnptr) {
    context->rip = insnptr;
}

static inline PAL_NUM pal_context_get_ip(PAL_CONTEXT *context) {
    return context->rip;
}

#endif /* PAL_ARCH_H */
