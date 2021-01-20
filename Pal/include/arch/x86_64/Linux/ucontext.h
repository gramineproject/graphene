/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */
#ifndef LINUX_X86_64_UCONTEXT_H_
#define LINUX_X86_64_UCONTEXT_H_

#include <stdint.h>

#include "api.h"
#include "assert.h"
#include "pal.h"

/* Structures definition source:
 * https://elixir.bootlin.com/linux/v5.10.3/source/include/uapi/asm-generic/ucontext.h */

#define UC_FP_XSTATE            1
#define UC_SIGCONTEXT_SS        2
#define UC_STRICT_RESTORE_SS    4

struct _fpstate {
    /* 64-bit FXSAVE format.  */
    uint16_t cwd;
    uint16_t swd;
    uint16_t twd;
    uint16_t fop;
    uint64_t rip;
    uint64_t rdp;
    uint32_t mxcsr;
    uint32_t mxcr_mask;
    uint32_t st_space[32];
    uint32_t xmm_space[64];
    uint32_t _reserved[24];
} __attribute__((packed, aligned(64)));

struct sigcontext {
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rbp;
    uint64_t rbx;
    uint64_t rdx;
    uint64_t rax;
    uint64_t rcx;
    uint64_t rsp;
    uint64_t rip;
    uint64_t eflags;
    union {
        struct {
            uint16_t cs;
            uint16_t gs;
            uint16_t fs;
            uint16_t ss;
        };
        uint64_t csgsfsss;
    };
    uint64_t err;
    uint64_t trapno;
    uint64_t oldmask;
    uint64_t cr2;
    struct _fpstate* fpstate;
    uint64_t reserved1[8];
};

typedef struct ucontext {
    unsigned long       uc_flags;
    struct ucontext*    uc_link;
    stack_t             uc_stack;
    struct sigcontext   uc_mcontext;
    __sigset_t          uc_sigmask;
} ucontext_t;

/* fpregs is shallow copied by only setting a pointer */
static inline void ucontext_to_pal_context(PAL_CONTEXT* context, ucontext_t* uc) {
    static_assert(offsetof(PAL_CONTEXT, fpregs) == offsetof(struct sigcontext, fpstate),
                  "This requires `PAL_CONTEXT` and `sigcontext` to have same layout");
    memcpy(context, &uc->uc_mcontext, offsetof(struct sigcontext, fpstate));
    context->fpregs = (PAL_XREGS_STATE*)uc->uc_mcontext.fpstate;
    context->is_fpregs_used = context->fpregs ? 1 : 0;
}

/* fpregs is shallow copied by only setting a pointer */
static inline void pal_context_to_ucontext(ucontext_t* uc, PAL_CONTEXT* context) {
    memcpy(&uc->uc_mcontext, context, offsetof(struct sigcontext, fpstate));
    uc->uc_mcontext.fpstate = context->is_fpregs_used ? (struct _fpstate*)context->fpregs : NULL;
}

static inline uint64_t ucontext_get_ip(ucontext_t* uc) {
    return uc->uc_mcontext.rip;
}

static inline void ucontext_set_function_parameters(ucontext_t* uc, void* func, uint64_t arg1,
                                                    uint64_t arg2) {
    uc->uc_mcontext.rip = (uint64_t)func;
    uc->uc_mcontext.rdi = arg1;
    uc->uc_mcontext.rsi = arg2;
}

#endif /* LINUX_X86_64_UCONTEXT_H_ */
