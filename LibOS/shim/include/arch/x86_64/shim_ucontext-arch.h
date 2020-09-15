/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef _SHIM_UCONTEXT_ARCH_H_
#define _SHIM_UCONTEXT_ARCH_H_

#include "shim_types.h"
#include "ucontext.h"

static inline void shim_regs_to_ucontext(ucontext_t* context, struct shim_regs* regs) {
    context->uc_mcontext.gregs[REG_R8]      = regs->r8;
    context->uc_mcontext.gregs[REG_R9]      = regs->r9;
    context->uc_mcontext.gregs[REG_R10]     = regs->r10;
    context->uc_mcontext.gregs[REG_R11]     = regs->r11;
    context->uc_mcontext.gregs[REG_R12]     = regs->r12;
    context->uc_mcontext.gregs[REG_R13]     = regs->r13;
    context->uc_mcontext.gregs[REG_R14]     = regs->r14;
    context->uc_mcontext.gregs[REG_R15]     = regs->r15;
    context->uc_mcontext.gregs[REG_RDI]     = regs->rdi;
    context->uc_mcontext.gregs[REG_RSI]     = regs->rsi;
    context->uc_mcontext.gregs[REG_RBP]     = regs->rbp;
    context->uc_mcontext.gregs[REG_RBX]     = regs->rbx;
    context->uc_mcontext.gregs[REG_RDX]     = regs->rdx;
    context->uc_mcontext.gregs[REG_RAX]     = regs->orig_rax;
    context->uc_mcontext.gregs[REG_RCX]     = regs->rcx;
    context->uc_mcontext.gregs[REG_RSP]     = regs->rsp;
    context->uc_mcontext.gregs[REG_RIP]     = regs->rip;
    context->uc_mcontext.gregs[REG_EFL]     = regs->rflags;
    context->uc_mcontext.gregs[REG_CSGSFS]  = 0;
    context->uc_mcontext.gregs[REG_ERR]     = 0;
    context->uc_mcontext.gregs[REG_TRAPNO]  = 0;
    context->uc_mcontext.gregs[REG_OLDMASK] = 0;
    context->uc_mcontext.gregs[REG_CR2]     = 0;
}

#endif /* _SHIM_UCONTEXT_ARCH_H_ */
