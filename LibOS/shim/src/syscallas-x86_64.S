/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

/*
 * This file contains the entry point of system call table in library OS (the function syscalldb()).
 *
 * The below entry point implementation first saves the CPU context of the current application
 * thread on the thread's LibOS stack, then calls the LibOS syscall-emulation function, which, upon
 * returning, calls context restoring function, which passes control back to the application.
 * The context consists of GPRs, FP control word (fpcw) and the SSE/AVX/... control word (mxcsr).
 *
 * Note that LibOS may clobber all FP/SSE/AVX/... (extended) state except the control words. We rely
 * on the fact that applications do *not* assume that this extended state is preserved across system
 * calls. Indeed, the extended state (bar control words) is explicitly described as *not* preserved
 * by the System V ABI, and though syscall ABI is not the same as System V ABI, we assume that no
 * sane application issues syscalls in a non-System-V compliant manner. See System V ABI docs
 * (https://uclibc.org/docs/psABI-x86_64.pdf), "Register Usage" for more information.
 */

#include "asm-offsets.h"

.extern shim_do_syscall
.extern shim_xstate_size
.extern shim_xstate_restore

# TODO: .cfi in this whole file is broken

.global syscalldb
.type syscalldb, @function
syscalldb:
    # on entry to this function rcx contains the return value (next instruction after syscall)
    # all other register can have arbitrary values
    .cfi_startproc
    .cfi_def_cfa %rsp, 0
    .cfi_register %rip, %rcx

    # We have to be very careful with executed instructions not to change any flags until they
    # are saved!

    # We can clobber r11 as it will be set to rflags later on.
    mov %rsp, %r11
    .cfi_undefined %r11
    .cfi_register %rsp, %r11
    .cfi_def_cfa_register %r11
    mov %gs:(SHIM_TCB_OFFSET + SHIM_TCB_LIBOS_STACK_OFF), %rsp

    # Create PAL_CONTEXT struct on the stack.

    # reserve space for mxcsr + fpcw + is_fpregs_used
    pushq $0

    # fpregs, but for now we use this to store rax - to get a scratch register
    push %rax

    # err + trapno + oldmask + cr2 are cleared for a syscall frame
    mov $0, %eax
    push %rax
    push %rax
    push %rax
    push %rax

    # csgsfsss - default value, as we do not support changing it
    mov $(0x2b << 48 | 0x33), %rax
    push %rax

    # after this we can use instructions changing flags
    pushfq
    # Debuggers use Trap Flag (TF) of EFLAGS to do single-stepping - otherwise it is unused by normal
    # applications. If the previous instruction was single-stepped, it stored TF, so reset it here.
    andq $~0x100, (%rsp)

    # Set default rflags value (just IF set).
    pushq $0x202
    popfq

    push %rcx # rip
    push %r11 # rsp

    # Set r11 to rflags
    mov 0x10(%rsp), %r11

    push %rcx

    # rax was saved in fpregs, save it in proper place now, fpregs will be populated later
    pushq 0x48(%rsp)

    push %rdx
    push %rbx
    push %rbp
    push %rsi
    push %rdi
    push %r15
    push %r14
    push %r13
    push %r12
    push %r11
    push %r10
    push %r9
    push %r8
    # PAL_CONTEXT struct ends here.

    # save FP Control Word & MXCSR into current thread's TCB
    stmxcsr PAL_CONTEXT_MXCSR_OFF(%rsp)
    fnstcw PAL_CONTEXT_FPCW_OFF(%rsp)

    # fpregs is not populated, so is_fpregs_used should be 0.
    movb $0, PAL_CONTEXT_FPREGS_USED_OFF(%rsp)

    call shim_xstate_size
    lea PAL_CONTEXT_FPREGS_OFF(%rsp), %rcx  # get address where to store fpregs pointer
    mov %rsp, %rdi                          # save pointer to PAL_CONTEXT
    sub %rax, %rsp                          # allocate space for xstate
    and $~(SHIM_XSTATE_ALIGN - 1), %rsp
    mov %rsp, (%rcx)

    and $~0xF, %rsp  # Required by System V AMD64 ABI.
    sub $8, %rsp
    xor %ebp, %ebp

    jmp shim_do_syscall # this does not return

    .cfi_endproc
    .size syscalldb, .-syscalldb

.global return_from_syscall
.type return_from_syscall, @function
return_from_syscall:
    # expects one argument (in `rdi`) - pointer to PAL_CONTEXT
    .cfi_startproc

    mov %rdi, %rbx

    movb PAL_CONTEXT_FPREGS_USED_OFF(%rbx), %al
    test %al, %al
    je .Lrestore_fpu_state

    mov PAL_CONTEXT_FPREGS_OFF(%rbx), %rdi
    call shim_xstate_restore
    jmp .Lrestore_context

.Lrestore_fpu_state:
    # restore FP Control Word & MXCSR from TCB
    fldcw PAL_CONTEXT_FPCW_OFF(%rbx)
    ldmxcsr PAL_CONTEXT_MXCSR_OFF(%rbx)

.Lrestore_context:
    mov %rbx, %rsp

    pop %r8
    pop %r9
    pop %r10
    pop %r11
    pop %r12
    pop %r13
    pop %r14
    pop %r15
    pop %rdi
    pop %rsi
    pop %rbp
    pop %rbx
    pop %rdx

    # exchange rcx with rip
    mov 0x8(%rsp), %rcx
    mov 0x18(%rsp), %rax
    mov %rcx, 0x18(%rsp)
    mov %rax, 0x8(%rsp)
    # exchange rsp with flags
    mov 0x10(%rsp), %rcx
    mov 0x20(%rsp), %rax
    mov %rcx, 0x20(%rsp)
    mov %rax, 0x10(%rsp)

    pop %rax
    pop %rcx # rip
    popfq
    mov %rcx, %gs:(SHIM_TCB_OFFSET + SHIM_TCB_SCRATCH_PC_OFF)
    pop %rcx
    pop %rsp
    jmp *%gs:(SHIM_TCB_OFFSET + SHIM_TCB_SCRATCH_PC_OFF)

    .cfi_endproc
    .size return_from_syscall, .-return_from_syscall
