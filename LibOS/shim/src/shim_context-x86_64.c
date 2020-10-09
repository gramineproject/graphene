/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * This file contains code for x86-specific CPU context manipulation.
 */

#include "shim_context.h"

#include "asm-offsets.h"
#include "shim_internal.h"

/* 512 for legacy regs, 64 for xsave header */
#define XSAVE_RESET_STATE_SIZE (512 + 64)

bool     g_shim_xsave_enabled  = false;
uint64_t g_shim_xsave_features = 0;
uint32_t g_shim_xsave_size     = 0;

const uint32_t g_shim_xsave_reset_state[XSAVE_RESET_STATE_SIZE / sizeof(uint32_t)]
__attribute__((aligned(SHIM_XSTATE_ALIGN))) = {
    0x037F, 0, 0, 0, 0, 0, 0x1F80,     0xFFFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,      0, 0, 0, 0, 0, 0,          0,      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,      0, 0, 0, 0, 0, 0,          0,      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,      0, 0, 0, 0, 0, 0,          0,      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,      0, 0, 0, 0, 0, 0,          0,      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,      0, 0, 0, 0, 0, 0x80000000, 0,      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    // XCOMP_BV[63] = 1, compaction mode
};

enum SHIM_CPUID_WORD {
    SHIM_CPUID_WORD_EAX = 0,
    SHIM_CPUID_WORD_EBX = 1,
    SHIM_CPUID_WORD_ECX = 2,
    SHIM_CPUID_WORD_EDX = 3,
    SHIM_CPUID_WORD_NUM = 4,
};

#define ECX_XSAVE   (1UL << 26)
#define ECX_OSXSAVE (1UL << 27)
#define XSAVE_CPUID 0x0000000d

void shim_xsave_init(void) {
    unsigned int value[4];
    if (!DkCpuIdRetrieve(0x1, 0, value))
        goto out;

    if (!(value[SHIM_CPUID_WORD_ECX] & ECX_XSAVE) || !(value[SHIM_CPUID_WORD_ECX] & ECX_OSXSAVE))
        goto out;

    if (!DkCpuIdRetrieve(XSAVE_CPUID, 0, value))
        goto out;

    uint32_t xsavesize = value[SHIM_CPUID_WORD_ECX];
    uint64_t xfeatures = value[SHIM_CPUID_WORD_EAX] |
                         (((uint64_t)value[SHIM_CPUID_WORD_EDX]) << 32);
    if (!xfeatures)
        goto out;

    if (xfeatures != SHIM_XFEATURE_MASK_FPSSE) {
        /* support more than just FP and SSE, can use XSAVE (it was introduced with AVX) */
        g_shim_xsave_enabled = true;
    }

    g_shim_xsave_features  = xfeatures;
    g_shim_xsave_size      = xsavesize;

out:
    debug("LibOS xsave_enabled %d, xsave_size 0x%x(%u), xsave_features 0x%lx\n",
          g_shim_xsave_enabled, g_shim_xsave_size, g_shim_xsave_size, g_shim_xsave_features);
}

void shim_xsave_save(struct shim_xregs_state* xregs_state) {
    assert(IS_ALIGNED_PTR(xregs_state, SHIM_XSTATE_ALIGN));

    if (g_shim_xsave_enabled) {
        long lmask = -1;
        long hmask = -1;
        memset(&xregs_state->header, 0, sizeof(xregs_state->header));
        __asm__ volatile("xsave64 (%0)" :: "r"(xregs_state), "a"(lmask), "d"(hmask) : "memory");
    } else {
        __asm__ volatile("fxsave64 (%0)" :: "r"(xregs_state) : "memory");
    }

    /* Emulate format for FP registers that Linux uses:
     * https://elixir.bootlin.com/linux/v5.4.13/source/arch/x86/kernel/fpu/signal.c#L86
     * https://elixir.bootlin.com/linux/v5.4.13/source/arch/x86/kernel/fpu/signal.c#L459 */
    struct shim_fpx_sw_bytes* fpx_sw = &xregs_state->fpstate.sw_reserved;
    fpx_sw->magic1        = SHIM_FP_XSTATE_MAGIC1;
    fpx_sw->extended_size = g_shim_xsave_size + SHIM_FP_XSTATE_MAGIC2_SIZE;
    fpx_sw->xfeatures     = g_shim_xsave_features;
    fpx_sw->xstate_size   = g_shim_xsave_size;
    memset(fpx_sw->padding, 0, sizeof(fpx_sw->padding));
    if (g_shim_xsave_enabled) {
        *((__typeof__(SHIM_FP_XSTATE_MAGIC2)*)((char*)xregs_state + fpx_sw->xstate_size)) =
            SHIM_FP_XSTATE_MAGIC2;
    }
}

void shim_xsave_restore(const struct shim_xregs_state* xregs_state) {
    assert(IS_ALIGNED_PTR(xregs_state, SHIM_XSTATE_ALIGN));
    if (g_shim_xsave_enabled) {
        long lmask = -1;
        long hmask = -1;
        __asm__ volatile("xrstor64 (%0)" :: "r"(xregs_state), "a"(lmask), "d"(hmask) : "memory");
    } else {
        __asm__ volatile("fxrstor64 (%0)" :: "r"(xregs_state) : "memory");
    }
}

void shim_xsave_reset(void) {
    shim_xsave_restore((struct shim_xregs_state*)g_shim_xsave_reset_state);
}

void restore_context(struct shim_context* context) {
    assert(context->regs);
    struct shim_regs regs = *context->regs;
    debug("restore context: SP = 0x%08lx, IP = 0x%08lx\n", regs.rsp, regs.rip);

    /* don't clobber redzone. If sigaltstack is used,
     * this area won't be clobbered by signal context */
    *(unsigned long*)(regs.rsp - RED_ZONE_SIZE - 8) = regs.rip;

    /* Ready to resume execution, re-enable preemption. */
    shim_tcb_t* tcb = shim_get_tcb();
    __enable_preempt(tcb);

    unsigned long fs_base = context->fs_base;
    memset(context, 0, sizeof(struct shim_context));
    context->fs_base = fs_base;

    __asm__ volatile("movq %0, %%rsp\r\n"
                     "addq $2 * 8, %%rsp\r\n"    /* skip orig_rax and rsp */
                     "popq %%r15\r\n"
                     "popq %%r14\r\n"
                     "popq %%r13\r\n"
                     "popq %%r12\r\n"
                     "popq %%r11\r\n"
                     "popq %%r10\r\n"
                     "popq %%r9\r\n"
                     "popq %%r8\r\n"
                     "popq %%rcx\r\n"
                     "popq %%rdx\r\n"
                     "popq %%rsi\r\n"
                     "popq %%rdi\r\n"
                     "popq %%rbx\r\n"
                     "popq %%rbp\r\n"
                     "popfq\r\n"
                     "movq "XSTRINGIFY(SHIM_REGS_RSP)" - "XSTRINGIFY(SHIM_REGS_RIP)"(%%rsp), %%rsp\r\n"
                     "movq $0, %%rax\r\n"
                     "jmp *-"XSTRINGIFY(RED_ZONE_SIZE)"-8(%%rsp)\r\n"
                     :: "g"(&regs) : "memory");
}

/*
 * See syscall_wrapper @ syscalldb.S and illegal_upcall() @ shim_signal.c
 * for details.
 * child thread can _not_ use parent stack. So return right after syscall
 * instruction as if syscall_wrapper is executed.
 */
void fixup_child_context(struct shim_regs* regs) {
    if (regs->rip == (unsigned long)&syscall_wrapper_after_syscalldb) {
        /*
         * we don't need to emulate stack pointer change because %rsp is
         * initialized to new child user stack passed to clone() system call.
         * See the caller of fixup_child_context().
         */
        /* regs->rsp += RED_ZONE_SIZE; */
        regs->rflags = regs->r11;
        regs->rip    = regs->rcx;
    }
}
