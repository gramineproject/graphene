#ifndef _SHIM_TCB_ARCH_H_
#define _SHIM_TCB_ARCH_H_

#include <stdint.h>

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

static inline uint64_t shim_regs_get_orig_reg(struct shim_regs* sr) {
    return sr->orig_rax;
}

static inline void shim_regs_set_orig_reg(struct shim_regs* sr, uint64_t orig_reg) {
    sr->orig_rax = orig_reg;
}

#endif /* _SHIM_TCB_ARCH_H_ */
