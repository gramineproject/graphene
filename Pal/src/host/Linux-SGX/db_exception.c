/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

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

/*
 * db_signal.c
 *
 * This file contains APIs to set up handlers of exceptions issued by the
 * host, and the methods to pass the exceptions to the upcalls.
 */

#include "pal_defs.h"
#include "pal_linux_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_error.h"
#include "pal_security.h"
#include "api.h"
#include "ecall_types.h"

#include <atomic.h>
#include <sigset.h>
#include <linux/signal.h>
#include <ucontext.h>

typedef struct exception_event {
    PAL_IDX             event_num;
    PAL_CONTEXT *       context;
    struct pal_frame *  frame;
} PAL_EVENT;

static void _DkGenericEventTrigger (PAL_IDX event_num, PAL_EVENT_HANDLER upcall,
                                    PAL_NUM arg, struct pal_frame * frame,
                                    PAL_CONTEXT * context)
{
    struct exception_event event;

    event.event_num = event_num;
    event.context = context;
    event.frame = frame;

    (*upcall) ((PAL_PTR) &event, arg, context);
}

static bool
_DkGenericSignalHandle (int event_num, PAL_NUM arg, struct pal_frame * frame,
                        PAL_CONTEXT * context)
{
    PAL_EVENT_HANDLER upcall = _DkGetExceptionHandler(event_num);

    if (upcall) {
        _DkGenericEventTrigger(event_num, upcall, arg, frame, context);
        return true;
    }

    return false;
}

#define ADDR_IN_PAL(addr)  \
        ((void *) (addr) > TEXT_START && (void *) (addr) < TEXT_END)

static struct pal_frame * get_frame (sgx_context_t * uc)
{
    unsigned long rbp;

    if (uc) {
        unsigned long rip = uc->rip;
        rbp = uc->rbp;

        if (!ADDR_IN_PAL(rip))
            return NULL;
    } else {
        __asm__ volatile ("movq %%rbp, %0" : "=r"(rbp) :: "memory");
    }

    while (ADDR_IN_PAL(((unsigned long *) rbp)[1]))
        rbp = *(unsigned long *) rbp;

    struct pal_frame * frame = (struct pal_frame *) rbp - 1;

    for (int i = 0 ; i < 8 ; i++) {
        if (frame->identifier == PAL_FRAME_IDENTIFIER)
            return frame;

        frame = (struct pal_frame *) ((void *) frame - 8);
    }

    return NULL;
}

__asm__ (".type arch_exception_return_asm, @function;"
     "arch_exception_return_asm:"
     "  pop %rax;"
     "  pop %rbx;"
     "  pop %rcx;"
     "  pop %rdx;"
     "  pop %rsi;"
     "  pop %rdi;"
     "  pop %r8;"
     "  pop %r9;"
     "  pop %r10;"
     "  pop %r11;"
     "  pop %r12;"
     "  pop %r13;"
     "  pop %r14;"
     "  pop %r15;"
     "  retq;");

extern void arch_exception_return (void) __asm__ ("arch_exception_return_asm");

void _DkExceptionRealHandler (int event, PAL_NUM arg, struct pal_frame * frame,
                              PAL_CONTEXT * context)
{
    if (frame) {
        frame = __alloca(sizeof(struct pal_frame));
        frame->identifier = PAL_FRAME_IDENTIFIER;
        frame->func     = &_DkExceptionRealHandler;
        frame->funcname = "_DkExceptionRealHandler";

        store_register(rsp, frame->arch.rsp);
        store_register(rbp, frame->arch.rbp);
        unsigned long * last_frame = ((unsigned long *) frame->arch.rbp) + 1;
        last_frame[0]  = (unsigned long) arch_exception_return;
        last_frame[1]  = context->rax;
        last_frame[2]  = context->rbx;
        last_frame[3]  = context->rcx;
        last_frame[4]  = context->rdx;
        last_frame[5]  = context->rsi;
        last_frame[6]  = context->rdi;
        last_frame[7]  = context->r8;
        last_frame[8]  = context->r9;
        last_frame[9]  = context->r10;
        last_frame[10] = context->r11;
        last_frame[11] = context->r12;
        last_frame[12] = context->r13;
        last_frame[13] = context->r14;
        last_frame[14] = context->r15;
        last_frame[15] = context->rip;
    }

    _DkGenericSignalHandle(event, arg, frame, context);
}

void restore_sgx_context (sgx_context_t * uc)
{
    /* prepare the return address */
    uc->rsp -= 8;
    *(uint64_t *) uc->rsp = uc->rip;

    /* now pop the stack */
    __asm__ volatile (
                  "mov %0, %%rsp\n"
                  "pop %%rax\n"
                  "pop %%rcx\n"
                  "pop %%rdx\n"
                  "pop %%rbx\n"
                  "add $8, %%rsp\n" /* don't pop RSP yet */
                  "pop %%rbp\n"
                  "pop %%rsi\n"
                  "pop %%rdi\n"
                  "pop %%r8\n"
                  "pop %%r9\n"
                  "pop %%r10\n"
                  "pop %%r11\n"
                  "pop %%r12\n"
                  "pop %%r13\n"
                  "pop %%r14\n"
                  "pop %%r15\n"
                  "popfq\n"
                  "mov -104(%%rsp), %%rsp\n"
                  "ret\n"
                  :: "r"(uc) : "memory");
}

/*
 * return value:
 *  true:  #UD is handled.
 *         the execution can be continued without propagating #UD.
 *  false: #UD is not handled.
 *         the exception needs to be raised up to LibOS or user application.
 */
static bool handle_ud(sgx_context_t * uc)
{
    uint8_t * instr = (uint8_t *) uc->rip;
    if (instr[0] == 0xcc) { /* skip int 3 */
        uc->rip++;
        return true;
    } else if (instr[0] == 0x0f && instr[1] == 0xa2) {
        /* cpuid */
        unsigned int values[4];
        if (!_DkCpuIdRetrieve(uc->rax & 0xffffffff,
                              uc->rcx & 0xffffffff, values)) {
            uc->rip += 2;
            uc->rax = values[0];
            uc->rbx = values[1];
            uc->rcx = values[2];
            uc->rdx = values[3];
            return true;
        }
    } else if (instr[0] == 0x0f && instr[1] == 0x31) {
        /* rdtsc */
        uc->rip += 2;
        uc->rdx = 0;
        uc->rax = 0;
        return true;
    } else if (instr[0] == 0x0f && instr[1] == 0x05) {
        /* syscall: LibOS may know how to handle this */
        return false;
    }
    SGX_DBG(DBG_E, "Unknown or illegal instruction at RIP 0x%016lx\n", uc->rip);
    return false;
}

void _DkExceptionHandler (unsigned int exit_info, sgx_context_t * uc)
{
    union {
        sgx_arch_exitinfo_t info;
        unsigned int intval;
    } ei = { .intval = exit_info };

    int event_num;
    PAL_CONTEXT * ctx;

    if (!ei.info.valid) {
        event_num = exit_info;
    } else {
        switch (ei.info.vector) {
        case SGX_EXCEPTION_VECTOR_BR:
            event_num = PAL_EVENT_NUM_BOUND;
            break;
        case SGX_EXCEPTION_VECTOR_UD:
            if (handle_ud(uc)) {
                restore_sgx_context(uc);
                return;
            }
            event_num = PAL_EVENT_ILLEGAL;
            break;
        case SGX_EXCEPTION_VECTOR_DE:
        case SGX_EXCEPTION_VECTOR_MF:
        case SGX_EXCEPTION_VECTOR_XM:
            event_num = PAL_EVENT_ARITHMETIC_ERROR;
            break;
        case SGX_EXCEPTION_VECTOR_AC:
            event_num = PAL_EVENT_MEMFAULT;
            break;
        case SGX_EXCEPTION_VECTOR_DB:
        case SGX_EXCEPTION_VECTOR_BP:
        default:
            restore_sgx_context(uc);
            return;
        }
    }

    if (ADDR_IN_PAL(uc->rip) &&
        /* event isn't asynchronous */
        (event_num != PAL_EVENT_QUIT &&
         event_num != PAL_EVENT_SUSPEND &&
         event_num != PAL_EVENT_RESUME)) {
        printf("*** An unexpected AEX vector occurred inside PAL. "
               "Exiting the thread. *** \n"
               "(vector = 0x%x, type = 0x%x valid = %d, RIP = +0x%08lx)\n"
               "rax: 0x%08lx rcx: 0x%08lx rdx: 0x%08lx rbx: 0x%08lx\n"
               "rsp: 0x%08lx rbp: 0x%08lx rsi: 0x%08lx rdi: 0x%08lx\n"
               "r8 : 0x%08lx r9 : 0x%08lx r10: 0x%08lx r11: 0x%08lx\n"
               "r12: 0x%08lx r13: 0x%08lx r14: 0x%08lx r15: 0x%08lx\n"
               "rflags: 0x%08lx rip: 0x%08lx\n",
               ei.info.vector, ei.info.type, ei.info.valid,
               uc->rip - (uintptr_t) TEXT_START,
               uc->rax, uc->rcx, uc->rdx, uc->rbx,
               uc->rsp, uc->rbp, uc->rsi, uc->rdi,
               uc->r8, uc->r9, uc->r10, uc->r11,
               uc->r12, uc->r13, uc->r14, uc->r15,
               uc->rflags, uc->rip);
#ifdef DEBUG
        printf("pausing for debug\n");
        while (true)
            __asm__ volatile("pause");
#endif
        _DkThreadExit();
    }

    ctx = __alloca(sizeof(PAL_CONTEXT));
    memset(ctx, 0, sizeof(PAL_CONTEXT));
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

    struct pal_frame * frame = get_frame(uc);

    PAL_NUM arg = 0;
    switch (event_num) {
    case PAL_EVENT_ILLEGAL:
        arg = uc->rip;
        break;
    case PAL_EVENT_MEMFAULT:
        /* TODO
         * SGX1 doesn't provide fault address.
         * SGX2 gives providing page. (lower address bits are masked)
         */
        break;
    default:
        /* nothing */
        break;
    }
    _DkExceptionRealHandler(event_num, arg, frame, ctx);
    restore_sgx_context(uc);
}

void _DkRaiseFailure (int error)
{
    PAL_EVENT_HANDLER upcall = _DkGetExceptionHandler(PAL_EVENT_FAILURE);

    if (!upcall)
        return;

    PAL_EVENT event;
    event.event_num = PAL_EVENT_FAILURE;
    event.context   = NULL;
    event.frame     = NULL;

    (*upcall) ((PAL_PTR) &event, error, NULL);
}

void _DkExceptionReturn (void * event)
{
    PAL_EVENT * e = event;
    sgx_context_t uc;
    PAL_CONTEXT * ctx = e->context;

    if (!ctx) {
        struct pal_frame * frame = e->frame;
        if (!frame)
            return;

        __clear_frame(frame);
        arch_restore_frame(&frame->arch);

        __asm__ volatile (
                      "xor %%rax, %%rax\r\n"
                      "leaveq\r\n"
                      "retq\r\n" ::: "memory");
    }

    uc.rax = ctx->rax;
    uc.rbx = ctx->rbx;
    uc.rcx = ctx->rcx;
    uc.rdx = ctx->rdx;
    uc.rsp = ctx->rsp;
    uc.rbp = ctx->rbp;
    uc.rsi = ctx->rsi;
    uc.rdi = ctx->rdi;
    uc.r8  = ctx->r8;
    uc.r9  = ctx->r9;
    uc.r10 = ctx->r10;
    uc.r11 = ctx->r11;
    uc.r12 = ctx->r12;
    uc.r13 = ctx->r13;
    uc.r14 = ctx->r14;
    uc.r15 = ctx->r15;
    uc.rflags = ctx->efl;
    uc.rip = ctx->rip;

    restore_sgx_context(&uc);
}

void _DkHandleExternalEvent (PAL_NUM event, sgx_context_t * uc)
{
    struct pal_frame * frame = get_frame(uc);

    if (event == PAL_EVENT_RESUME &&
        frame && frame->func == DkObjectsWaitAny)
        return;

    if (!frame) {
        frame = __alloca(sizeof(struct pal_frame));
        frame->identifier = PAL_FRAME_IDENTIFIER;
        frame->func = &_DkHandleExternalEvent;
        frame->funcname = "_DkHandleExternalEvent";
        arch_store_frame(&frame->arch);
    }

    if (!_DkGenericSignalHandle(event, 0, frame, NULL)
        && event != PAL_EVENT_RESUME)
        _DkThreadExit();
}
