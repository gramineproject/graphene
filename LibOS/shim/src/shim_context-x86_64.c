/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * This file contains code for x86_64-specific CPU context manipulation.
 */

#include <stdnoreturn.h>

#include "asm-offsets.h"
#include "pal.h"
#include "shim_context.h"
#include "shim_internal.h"

/* 512 for legacy regs, 64 for xsave header */
#define XSTATE_RESET_SIZE (512 + 64)

bool     g_shim_xsave_enabled  = false;
uint64_t g_shim_xsave_features = 0;
uint32_t g_shim_xsave_size     = 0;

const uint32_t g_shim_xstate_reset_state[XSTATE_RESET_SIZE / sizeof(uint32_t)]
__attribute__((aligned(SHIM_XSTATE_ALIGN))) = {
    0x037F, 0, 0, 0, 0, 0, 0x1F80,     0xFFFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,      0, 0, 0, 0, 0, 0,          0,      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,      0, 0, 0, 0, 0, 0,          0,      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,      0, 0, 0, 0, 0, 0,          0,      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,      0, 0, 0, 0, 0, 0,          0,      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,      0, 0, 0, 0, 0, 0x80000000, 0,      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    // XCOMP_BV[63] = 1, compaction mode
};

#define CPUID_FEATURE_XSAVE   (1UL << 26)
#define CPUID_FEATURE_OSXSAVE (1UL << 27)

#define CPUID_LEAF_PROCINFO 0x00000001
#define CPUID_LEAF_XSAVE 0x0000000d

void shim_xstate_init(void) {
    /* by default, fall back to old-style FXSAVE (if cannot deduce from CPUID below) */
    g_shim_xsave_enabled  = false;
    g_shim_xsave_features = SHIM_XFEATURE_MASK_FPSSE;
    g_shim_xsave_size     = XSTATE_RESET_SIZE;

    unsigned int value[4];
    if (!DkCpuIdRetrieve(CPUID_LEAF_PROCINFO, 0, value))
        goto out;

    if (!(value[PAL_CPUID_WORD_ECX] & CPUID_FEATURE_XSAVE) ||
        !(value[PAL_CPUID_WORD_ECX] & CPUID_FEATURE_OSXSAVE))
        goto out;

    if (!DkCpuIdRetrieve(CPUID_LEAF_XSAVE, 0, value))
        goto out;

    uint32_t xsavesize = value[PAL_CPUID_WORD_ECX];
    uint64_t xfeatures = value[PAL_CPUID_WORD_EAX] |
                         ((uint64_t)value[PAL_CPUID_WORD_EDX] << 32);
    if (!xsavesize || !xfeatures) {
        /* could not read xfeatures; fall back to old-style FXSAVE */
        goto out;
    }

    if (xfeatures & ~SHIM_XFEATURE_MASK_FPSSE) {
        /* support more than just FP and SSE, can use XSAVE (it was introduced with AVX) */
        g_shim_xsave_enabled = true;
    }

    g_shim_xsave_features  = xfeatures;
    g_shim_xsave_size      = xsavesize;

out:
    debug("LibOS xsave_enabled %d, xsave_size 0x%x(%u), xsave_features 0x%lx\n",
          g_shim_xsave_enabled, g_shim_xsave_size, g_shim_xsave_size, g_shim_xsave_features);
}

void shim_xstate_save(void* xstate_extended) {
    assert(IS_ALIGNED_PTR(xstate_extended, SHIM_XSTATE_ALIGN));

    struct shim_xstate* xstate = (struct shim_xstate*)xstate_extended;
    char* bytes_after_xstate   = (char*)xstate_extended + g_shim_xsave_size;

    if (g_shim_xsave_enabled) {
        memset(&xstate->xstate_hdr, 0, sizeof(xstate->xstate_hdr));
        __builtin_ia32_xsave64(xstate, /*mask=*/-1LL);
    } else {
        __builtin_ia32_fxsave64(xstate);
    }

    /* Emulate software format for bytes 464..511 in the 512-byte layout of the FXSAVE/FXRSTOR
     * frame that Linux uses for x86-64:
     *   https://elixir.bootlin.com/linux/v5.9/source/arch/x86/kernel/fpu/signal.c#L86
     *   https://elixir.bootlin.com/linux/v5.9/source/arch/x86/kernel/fpu/signal.c#L517
     *
     * This format is assumed by Glibc; this will also be useful if we implement checks in LibOS
     * similar to Linux's check_for_xstate(). Note that we don't care about CPUs older than
     * FXSAVE-enabled (so-called "legacy frames"), therefore we always use MAGIC1 and MAGIC2. */
    struct shim_fpx_sw_bytes* fpx_sw = &xstate->fpstate.sw_reserved;
    fpx_sw->magic1        = SHIM_FP_XSTATE_MAGIC1;
    fpx_sw->extended_size = g_shim_xsave_size + SHIM_FP_XSTATE_MAGIC2_SIZE;
    fpx_sw->xfeatures     = g_shim_xsave_features;
    fpx_sw->xstate_size   = g_shim_xsave_size;
    memset(&fpx_sw->padding, 0, sizeof(fpx_sw->padding));

    /* the last 32-bit word of the extended FXSAVE/XSAVE area (at the xstate + extended_size
     * - FP_XSTATE_MAGIC2_SIZE address) is set to FP_XSTATE_MAGIC2 so that app/Graphene can sanity
     * check FXSAVE/XSAVE size calculations */
    *((__typeof__(SHIM_FP_XSTATE_MAGIC2)*)bytes_after_xstate) = SHIM_FP_XSTATE_MAGIC2;
}

void shim_xstate_restore(const void* xstate_extended) {
    assert(IS_ALIGNED_PTR(xstate_extended, SHIM_XSTATE_ALIGN));

    struct shim_xstate* xstate = (struct shim_xstate*)xstate_extended;
    char* bytes_after_xstate   = (char*)xstate_extended + g_shim_xsave_size;

    struct shim_fpx_sw_bytes* fpx_sw = &xstate->fpstate.sw_reserved;
    assert(fpx_sw->magic1 == SHIM_FP_XSTATE_MAGIC1);
    assert(fpx_sw->extended_size == g_shim_xsave_size + SHIM_FP_XSTATE_MAGIC2_SIZE);
    assert(fpx_sw->xfeatures == g_shim_xsave_features);
    assert(fpx_sw->xstate_size == g_shim_xsave_size);
    assert(*((__typeof__(SHIM_FP_XSTATE_MAGIC2)*)bytes_after_xstate) == SHIM_FP_XSTATE_MAGIC2);

    __UNUSED(bytes_after_xstate);
    __UNUSED(fpx_sw);

    if (g_shim_xsave_enabled)
        __builtin_ia32_xrstor64(xstate, /*mask=*/-1LL);
    else
        __builtin_ia32_fxrstor64(xstate);
}

void shim_xstate_reset(void) {
    shim_xstate_restore(g_shim_xstate_reset_state);
}

noreturn void restore_child_context_after_clone(struct shim_context* context) {
    assert(context->regs);
    struct shim_regs regs = *context->regs;
    debug("restore context: SP = 0x%08lx, IP = 0x%08lx\n", regs.rsp, regs.rip);

    /* don't clobber redzone. If sigaltstack is used,
     * this area won't be clobbered by signal context */
    *(unsigned long*)(regs.rsp - RED_ZONE_SIZE - 8) = regs.rip;

    context->regs = NULL;

    /* Ready to resume execution, re-enable preemption. */
    shim_tcb_t* tcb = shim_get_tcb();
    __enable_preempt(tcb);

    __asm__ volatile("fldcw (%0)\r\n" /* restore FP (fpcw) and SSE/AVX/... (mxcsr) control words */
                     "ldmxcsr (%1)\r\n"
                     "movq %2, %%rsp\r\n"
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
                     :: "g"(&context->ext_ctx.fpcw), "g"(&context->ext_ctx.mxcsr), "g"(&regs) : "memory");

    __builtin_unreachable();
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
