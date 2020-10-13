#ifndef _SHIM_TCB_ARCH_H_
#define _SHIM_TCB_ARCH_H_

#include <stdint.h>

#include "pal.h"

struct shim_regs {
    uint64_t orig_rax;
    uint64_t rsp;
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t r11;
    uint64_t r10;
    uint64_t r9;
    uint64_t r8;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t rbx;
    uint64_t rbp;
    uint64_t rflags;
    uint64_t rip;
};

/* adopt Linux-style FP layout (_libc_fpstate of glibc): self-contained definition is needed for
 * LibOS, so define the exact same layout with shim prefix */
#define SHIM_FP_XSTATE_MAGIC1      0x46505853U
#define SHIM_FP_XSTATE_MAGIC2      0x46505845U
#define SHIM_FP_XSTATE_MAGIC2_SIZE (sizeof(SHIM_FP_XSTATE_MAGIC2))

#define SHIM_XSTATE_ALIGN 64

enum SHIM_XFEATURE {
    SHIM_XFEATURE_FP,
    SHIM_XFEATURE_SSE,
    SHIM_XFEATURE_YMM,
    SHIM_XFEATURE_BNDREGS,
    SHIM_XFEATURE_BNDCSR,
    SHIM_XFEATURE_OPMASK,
    SHIM_XFEATURE_ZMM_Hi256,
    SHIM_XFEATURE_Hi16_ZMM,
    SHIM_XFEATURE_PT,
    SHIM_XFEATURE_PKRU,
    SHIM_XFEATURE_MAX,
};

#define SHIM_XFEATURE_MASK_FP        (1UL << SHIM_XFEATURE_FP)
#define SHIM_XFEATURE_MASK_SSE       (1UL << SHIM_XFEATURE_SSE)
#define SHIM_XFEATURE_MASK_YMM       (1UL << SHIM_XFEATURE_YMM)
#define SHIM_XFEATURE_MASK_BNDREGS   (1UL << SHIM_XFEATURE_BNDREGS)
#define SHIM_XFEATURE_MASK_BNDCSR    (1UL << SHIM_XFEATURE_BNDCSR)
#define SHIM_XFEATURE_MASK_OPMASK    (1UL << SHIM_XFEATURE_OPMASK)
#define SHIM_XFEATURE_MASK_ZMM_Hi256 (1UL << SHIM_XFEATURE_ZMM_Hi256)
#define SHIM_XFEATURE_MASK_Hi16_ZMM  (1UL << SHIM_XFEATURE_Hi16_ZMM)
#define SHIM_XFEATURE_MASK_PT        (1UL << SHIM_XFEATURE_PT)
#define SHIM_XFEATURE_MASK_PKRU      (1UL << SHIM_XFEATURE_PKRU)

#define SHIM_XFEATURE_MASK_FPSSE     (SHIM_XFEATURE_MASK_FP | SHIM_XFEATURE_MASK_SSE)
#define SHIM_XFEATURE_MASK_AVX512    (SHIM_XFEATURE_MASK_OPMASK | SHIM_XFEATURE_MASK_ZMM_Hi256 \
                                      | SHIM_XFEATURE_MASK_Hi16_ZMM)

struct shim_fpx_sw_bytes {
    uint32_t magic1;        /*!< SHIM_FP_XSTATE_MAGIC1 */
    uint32_t extended_size; /*!< g_shim_xsave_size */
    uint64_t xfeatures;     /*!< XSAVE feature */
    uint32_t xstate_size;   /*!< g_xsave_size + SHIM_FP_STATE_MAGIC2_SIZE */
    uint32_t padding[7];
};

struct shim_fpxreg {
    uint16_t significand[4];
    uint16_t exponent;
    uint16_t padding[3];
};

struct shim_xmmreg {
    uint32_t element[4];
};

/* 64-bit FXSAVE format */
struct shim_fpstate {
    uint16_t cwd;
    uint16_t swd;
    uint16_t ftw;
    uint16_t fop;
    uint64_t rip;
    uint64_t rdp;
    uint32_t mxcsr;
    uint32_t mxcr_mask;
    struct shim_fpxreg st[8];
    struct shim_xmmreg xmm[16];
    union {
        uint32_t padding[24];
        struct {
            uint32_t padding2[12];
            struct shim_fpx_sw_bytes sw_reserved;
        };
    };
};

struct shim_xstate_header {
    uint64_t xfeatures;
    uint64_t xcomp_bv;
    uint64_t reserved[6];
} __attribute__((packed));

struct shim_xregs_state {
    struct shim_fpstate fpstate;
    struct shim_xstate_header header;
} __attribute__((packed, aligned(SHIM_XSTATE_ALIGN)));

static inline uint64_t shim_regs_get_sp(struct shim_regs* sr) {
    return sr->rsp;
}

static inline void shim_regs_set_sp(struct shim_regs* sr, uint64_t sp) {
    sr->rsp = sp;
}

static inline uint64_t shim_regs_get_ip(struct shim_regs* sr) {
    return sr->rip;
}

static inline uint64_t shim_regs_get_syscallnr(struct shim_regs* sr) {
    return sr->orig_rax;
}

static inline void shim_regs_set_syscallnr(struct shim_regs* sr, uint64_t sc_num) {
    sr->orig_rax = sc_num;
}

#define SHIM_TCB_GET(member)                                            \
    ({                                                                  \
        shim_tcb_t* tcb;                                                \
        __typeof__(tcb->member) ret;                                    \
        static_assert(sizeof(ret) == 8 ||                               \
                      sizeof(ret) == 4 ||                               \
                      sizeof(ret) == 2 ||                               \
                      sizeof(ret) == 1,                                 \
                      "SHIM_TCB_GET can be used only for "              \
                      "8, 4, 2, or 1-byte(s) members");                 \
        switch (sizeof(ret)) {                                          \
        case 8:                                                         \
            __asm__("movq %%gs:%c1, %0\n"                               \
                    : "=r"(ret)                                         \
                    : "i" (offsetof(PAL_TCB, libos_tcb) +               \
                           offsetof(shim_tcb_t, member)));              \
            break;                                                      \
        case 4:                                                         \
            __asm__("movl %%gs:%c1, %0\n"                               \
                    : "=r"(ret)                                         \
                    : "i" (offsetof(PAL_TCB, libos_tcb) +               \
                           offsetof(shim_tcb_t, member)));              \
            break;                                                      \
        case 2:                                                         \
            __asm__("movw %%gs:%c1, %0\n"                               \
                    : "=r"(ret)                                         \
                    : "i" (offsetof(PAL_TCB, libos_tcb) +               \
                           offsetof(shim_tcb_t, member)));              \
            break;                                                      \
        case 1:                                                         \
            __asm__("movb %%gs:%c1, %0\n"                               \
                    : "=r"(ret)                                         \
                    : "i" (offsetof(PAL_TCB, libos_tcb) +               \
                           offsetof(shim_tcb_t, member)));              \
            break;                                                      \
        default:                                                        \
            __abort();                                                  \
        }                                                               \
        ret;                                                            \
    })

#define SHIM_TCB_SET(member, value)                                     \
    do {                                                                \
        shim_tcb_t* tcb;                                                \
        static_assert(sizeof(tcb->member) == 8 ||                       \
                      sizeof(tcb->member) == 4 ||                       \
                      sizeof(tcb->member) == 2 ||                       \
                      sizeof(tcb->member) == 1,                         \
                      "SHIM_TCB_SET can be used only for "              \
                      "8, 4, 2, or 1-byte(s) members");                 \
        switch (sizeof(tcb->member)) {                                  \
        case 8:                                                         \
            __asm__("movq %0, %%gs:%c1\n"                               \
                    :: "ir"(value),                                     \
                     "i"(offsetof(PAL_TCB, libos_tcb) +                 \
                         offsetof(shim_tcb_t, member)));                \
            break;                                                      \
        case 4:                                                         \
            __asm__("movl %0, %%gs:%c1\n"                               \
                    :: "ir"(value),                                     \
                     "i"(offsetof(PAL_TCB, libos_tcb) +                 \
                         offsetof(shim_tcb_t, member)));                \
            break;                                                      \
        case 2:                                                         \
            __asm__("movw %0, %%gs:%c1\n"                               \
                    :: "ir"(value),                                     \
                     "i"(offsetof(PAL_TCB, libos_tcb) +                 \
                         offsetof(shim_tcb_t, member)));                \
            break;                                                      \
        case 1:                                                         \
            __asm__("movb %0, %%gs:%c1\n"                               \
                    :: "ir"(value),                                     \
                     "i"(offsetof(PAL_TCB, libos_tcb) +                 \
                         offsetof(shim_tcb_t, member)));                \
            break;                                                      \
        default:                                                        \
            __abort();                                                  \
        }                                                               \
    } while (0)

static inline void shim_arch_update_fs_base(unsigned long fs_base) {
    DkSegmentRegister(PAL_SEGMENT_FS, (PAL_PTR)fs_base);
}

/* On x86_64 the fs_base is the same as the tls parameter to 'clone' */
static inline unsigned long tls_to_fs_base(unsigned long tls) {
    return tls;
}

#endif /* _SHIM_TCB_ARCH_H_ */
