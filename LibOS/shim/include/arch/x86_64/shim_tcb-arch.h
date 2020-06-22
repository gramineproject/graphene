#ifndef _SHIM_TCB_ARCH_H_
#define _SHIM_TCB_ARCH_H_

#include <stdint.h>

#include "pal.h"

struct shim_regs {
    uint64_t    orig_rax;
    uint64_t    rsp;
    uint64_t    r15;
    uint64_t    r14;
    uint64_t    r13;
    uint64_t    r12;
    uint64_t    r11;
    uint64_t    r10;
    uint64_t    r9;
    uint64_t    r8;
    uint64_t    rcx;
    uint64_t    rdx;
    uint64_t    rsi;
    uint64_t    rdi;
    uint64_t    rbx;
    uint64_t    rbp;
    uint64_t    rflags;
    uint64_t    rip;
};

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
