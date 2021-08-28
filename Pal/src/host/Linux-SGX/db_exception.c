/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 *               2020 Intel Labs
 */

/*
 * This file contains APIs to set up signal handlers.
 */

#include <stddef.h> /* needed by <linux/signal.h> for size_t */
#include <linux/signal.h>

#include "api.h"
#include "cpu.h"
#include "ecall_types.h"
#include "pal.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_security.h"
#include "sigset.h"
#include "ucontext.h"

#define ADDR_IN_PAL(addr) ((void*)(addr) > TEXT_START && (void*)(addr) < TEXT_END)

static void restore_pal_context(sgx_pal_gpr_t* uc, PAL_CONTEXT* ctx) {
    uc->rax    = ctx->rax;
    uc->rbx    = ctx->rbx;
    uc->rcx    = ctx->rcx;
    uc->rdx    = ctx->rdx;
    uc->rsp    = ctx->rsp;
    uc->rbp    = ctx->rbp;
    uc->rsi    = ctx->rsi;
    uc->rdi    = ctx->rdi;
    uc->r8     = ctx->r8;
    uc->r9     = ctx->r9;
    uc->r10    = ctx->r10;
    uc->r11    = ctx->r11;
    uc->r12    = ctx->r12;
    uc->r13    = ctx->r13;
    uc->r14    = ctx->r14;
    uc->r15    = ctx->r15;
    uc->rflags = ctx->efl;
    uc->rip    = ctx->rip;

    /* FPU/SSE "extended" context was copied by reference. */
}

static void save_pal_context(PAL_CONTEXT* ctx, sgx_pal_gpr_t* uc, PAL_XREGS_STATE* xregs_state) {
    memset(ctx, 0, sizeof(*ctx));

    ctx->rax = uc->rax;
    ctx->rbx = uc->rbx;
    ctx->rcx = uc->rcx;
    ctx->rdx = uc->rdx;
    ctx->rsp = uc->rsp;
    ctx->rbp = uc->rbp;
    ctx->rsi = uc->rsi;
    ctx->rdi = uc->rdi;
    ctx->r8  = uc->r8;
    ctx->r9  = uc->r9;
    ctx->r10 = uc->r10;
    ctx->r11 = uc->r11;
    ctx->r12 = uc->r12;
    ctx->r13 = uc->r13;
    ctx->r14 = uc->r14;
    ctx->r15 = uc->r15;
    ctx->efl = uc->rflags;
    ctx->rip = uc->rip;
    union pal_csgsfs csgsfs = {
        .cs = 0x33, // __USER_CS(5) | 0(GDT) | 3(RPL)
        .fs = 0,
        .gs = 0,
        .ss = 0x2b, // __USER_DS(6) | 0(GDT) | 3(RPL)
    };
    ctx->csgsfsss = csgsfs.csgsfs;

    assert(xregs_state);
    ctx->fpregs = xregs_state;
    ctx->is_fpregs_used = 1;

    /* Emulate format for fp registers Linux sets up as signal frame.
     * https://elixir.bootlin.com/linux/v5.4.13/source/arch/x86/kernel/fpu/signal.c#L86
     * https://elixir.bootlin.com/linux/v5.4.13/source/arch/x86/kernel/fpu/signal.c#L459
     */
    PAL_FPX_SW_BYTES* fpx_sw = &xregs_state->fpstate.sw_reserved;
    fpx_sw->magic1        = PAL_FP_XSTATE_MAGIC1;
    fpx_sw->extended_size = g_xsave_size;
    fpx_sw->xfeatures     = g_xsave_features;
    memset(fpx_sw->padding, 0, sizeof(fpx_sw->padding));
    if (g_xsave_enabled) {
        fpx_sw->xstate_size = g_xsave_size + PAL_FP_XSTATE_MAGIC2_SIZE;
        *(__typeof__(PAL_FP_XSTATE_MAGIC2)*)((void*)xregs_state + g_xsave_size) =
            PAL_FP_XSTATE_MAGIC2;
    } else {
        fpx_sw->xstate_size = g_xsave_size;
    }
}

static void emulate_rdtsc_and_print_warning(sgx_pal_gpr_t* uc) {
    static int first = 0;
    if (__atomic_exchange_n(&first, 1, __ATOMIC_RELAXED) == 0) {
        /* if we end up emulating RDTSC/RDTSCP instruction, we cannot use invariant TSC */
        extern uint64_t g_tsc_hz;
        g_tsc_hz = 0;
        log_warning("all RDTSC/RDTSCP instructions are emulated (imprecisely) via gettime() "
                    "syscall.");
    }

    uint64_t usec;
    int res = _DkSystemTimeQuery(&usec);
    if (res < 0) {
        log_error("_DkSystemTimeQuery() failed in unrecoverable context, exiting.");
        _DkProcessExit(1);
    }
    /* FIXME: Ideally, we would like to scale microseconds back to RDTSC clock cycles */
    uc->rdx = (uint32_t)(usec >> 32);
    uc->rax = (uint32_t)usec;
}

/* return value: true if #UD was handled and execution can be continued without propagating #UD;
 *               false if #UD was not handled and exception needs to be raised up to LibOS/app */
static bool handle_ud(sgx_pal_gpr_t* uc) {
    uint8_t* instr = (uint8_t*)uc->rip;
    if (instr[0] == 0x0f && instr[1] == 0xa2) {
        /* cpuid */
        unsigned int values[4];
        if (!_DkCpuIdRetrieve(uc->rax & 0xffffffff, uc->rcx & 0xffffffff, values)) {
            uc->rip += 2;
            uc->rax = values[0];
            uc->rbx = values[1];
            uc->rcx = values[2];
            uc->rdx = values[3];
            return true;
        }
    } else if (instr[0] == 0x0f && instr[1] == 0x31) {
        /* rdtsc */
        emulate_rdtsc_and_print_warning(uc);
        uc->rip += 2;
        return true;
    } else if (instr[0] == 0x0f && instr[1] == 0x01 && instr[2] == 0xf9) {
        /* rdtscp */
        emulate_rdtsc_and_print_warning(uc);
        uc->rip += 3;
        uc->rcx = 0; /* dummy IA32_TSC_AUX; Linux encodes it as (numa_id << 12) | cpu_id */
        return true;
    } else if (instr[0] == 0xf3 && (instr[1] & ~1) == 0x48 && instr[2] == 0x0f &&
               instr[3] == 0xae && instr[4] >> 6 == 0b11 && ((instr[4] >> 3) & 0b111) < 4) {
        /* A disabled {RD,WR}{FS,GS}BASE instruction generated a #UD */
        log_error(
            "{RD,WR}{FS,GS}BASE instructions are not permitted on this platform. Please check the "
            "instructions under \"Building with SGX support\" from Graphene documentation.");
        return false;
    } else if (instr[0] == 0x0f && instr[1] == 0x05) {
        /* syscall: LibOS may know how to handle this */
        return false;
    }
    log_error("Unknown or illegal instruction executed");
    return false;
}

void _DkExceptionHandler(unsigned int urts_event, sgx_pal_gpr_t* uc, PAL_XREGS_STATE* xregs_state) {
    assert(IS_ALIGNED_PTR(xregs_state, PAL_XSTATE_ALIGN));
    assert(GET_ENCLAVE_TLS(cssa) == 2);

    if (urts_event == 0 || urts_event >= PAL_EVENT_NUM_BOUND) {
        log_error("Illegal exception reported by untrusted PAL: %d", urts_event);
        _DkProcessExit(1);
    }

    union {
        sgx_arch_exit_info_t info;
        uint32_t intval;
    } ei = { .intval = GET_ENCLAVE_SSA_GPR(1)->exitinfo };

    unsigned int event_num = 0;
    if (!ei.info.valid) {
        event_num = urts_event;
    } else {
        switch (ei.info.vector) {
            case SGX_EXCEPTION_VECTOR_BR:
                log_error("Handling #BR exceptions is currently unsupported by Graphene");
                _DkProcessExit(1);
            case SGX_EXCEPTION_VECTOR_UD:
                if (handle_ud(uc)) {
                    return;
                }
                event_num = PAL_EVENT_ILLEGAL;
                break;
            case SGX_EXCEPTION_VECTOR_DE:
                if (uc->rip == (uint64_t)&sgx_ocall_div) {
                    event_num = urts_event;
                    break;
                }
                /* Fallthrough. */
            case SGX_EXCEPTION_VECTOR_MF:
            case SGX_EXCEPTION_VECTOR_XM:
                event_num = PAL_EVENT_ARITHMETIC_ERROR;
                break;
            case SGX_EXCEPTION_VECTOR_AC:
                event_num = PAL_EVENT_MEMFAULT;
                break;
            case SGX_EXCEPTION_VECTOR_DB:
            case SGX_EXCEPTION_VECTOR_BP:
                return;
            default:
                log_error("Unknown exception reported by HW: %u", ei.info.vector);
                return;
        }
    }
    assert(event_num);

    if (ADDR_IN_PAL(uc->rip) &&
        /* event isn't asynchronous (i.e., synchronous exception) */
        event_num != PAL_EVENT_QUIT &&
        event_num != PAL_EVENT_INTERRUPTED) {
        log_error("*** Unexpected exception occurred inside PAL at RIP = +0x%08lx! ***",
                  uc->rip - (uintptr_t)TEXT_START);

        if (ei.info.valid) {
            /* EXITINFO field: vector = exception number, exit_type = 0x3 for HW / 0x6 for SW */
            log_debug("(SGX HW reported AEX vector 0x%x with exit_type = 0x%x)", ei.info.vector,
                      ei.info.exit_type);
        } else {
            log_debug("(untrusted PAL sent PAL event 0x%x)", ei.intval);
        }

        _DkProcessExit(1);
    }

    PAL_CONTEXT ctx;
    save_pal_context(&ctx, uc, xregs_state);

    /* TODO: save EXINFO from MISC region and populate below fields */
    ctx.err     = 0;
    ctx.trapno  = ei.info.valid ? ei.info.vector : 0;
    ctx.oldmask = 0;
    ctx.cr2     = 0;

    PAL_NUM addr = 0;
    switch (event_num) {
        case PAL_EVENT_ILLEGAL:
            addr = uc->rip;
            break;
        case PAL_EVENT_MEMFAULT:
            /* TODO: SGX1 doesn't provide fault address but SGX2 does (with lower bits masked) */
            break;
        default:
            break;
    }

    PAL_EVENT_HANDLER upcall = _DkGetExceptionHandler(event_num);
    if (upcall) {
        (*upcall)(ADDR_IN_PAL(uc->rip), addr, &ctx);
    }

    restore_pal_context(uc, &ctx);

    /* Make sure we handle the HW exception only once. */
    GET_ENCLAVE_SSA_GPR(1)->exitinfo = 0;
}
