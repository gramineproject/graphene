/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * syscallas.S
 *
 * This file contains the entry point of system call table in library OS.
 */

#include <shim_defs.h>
#include <shim_unistd_defs.h>

#include "asm-offsets.h"

        .global syscalldb
        .type syscalldb, @function
        .extern shim_table, debug_unsupp
        .global syscall_wrapper
        .type syscall_wrapper, @function
        .global syscall_wrapper_after_syscalldb
        .type syscall_wrapper_after_syscalldb, @function

syscalldb:
        .cfi_startproc

        # Create shim_regs struct on the stack.
        pushfq

        # Under GDB, single-stepping sets Trap Flag (TP) of EFLAGS,
        # thus TP=1 is stored on pushfq above. Upon consequent popfq,
        # TP is 1, resulting in spurious trap. Reset TP here.
        andq $~0x100, (%rsp)

        cld
        pushq %rbp
        pushq %rbx
        pushq %rdi
        pushq %rsi
        pushq %rdx
        pushq %rcx
        pushq %r8
        pushq %r9
        pushq %r10
        pushq %r11
        pushq %r12
        pushq %r13
        pushq %r14
        pushq %r15
        leaq SHIM_REGS_SIZE - SHIM_REGS_R15(%rsp), %rbx
        pushq %rbx
        pushq %rax
        # shim_regs struct ends here.

        movq %rsp, %rbp
        .cfi_def_cfa_offset SHIM_REGS_SIZE
        .cfi_offset %rbp, -3 * 8    # saved_rbp is at CFA-24 (saved_rflags + saved_rbp)
        .cfi_def_cfa_register %rbp  # %rbp

        cmp $LIBOS_SYSCALL_BOUND, %rax
        jae isundef

        movq shim_table@GOTPCREL(%rip), %rbx
        movq (%rbx,%rax,8), %rbx
        cmp $0, %rbx
        je isundef

        movq %rbp, %gs:(SHIM_TCB_OFFSET + TCB_REGS)

        /* Translating x86_64 kernel calling convention to user-space
         * calling convention */
        movq %r10, %rcx
        andq $~0xF, %rsp  # Required by System V AMD64 ABI.
        call *%rbx

        movq $0, %gs:(SHIM_TCB_OFFSET + TCB_REGS)

ret:
        movq %rbp, %rsp
        addq $2 * 8, %rsp   # skip orig_rax and rsp
        popq %r15
        popq %r14
        popq %r13
        popq %r12
        popq %r11
        popq %r10
        popq %r9
        popq %r8
        popq %rcx
        popq %rdx
        popq %rsi
        popq %rdi
        popq %rbx
        popq %rbp
        .cfi_def_cfa %rsp, 2 * 8  # +8 for ret_addr, +8 for saved_rflags
        popfq
        .cfi_def_cfa_offset 8     # +8 for ret_addr
        retq

isundef:
#ifdef DEBUG
        mov %rax, %rdi
        andq $~0xF, %rsp  # Required by System V AMD64 ABI.
        call *debug_unsupp@GOTPCREL(%rip)
#endif
        movq $-38, %rax  # ENOSYS
        jmp ret

        .cfi_endproc
        .size syscalldb, .-syscalldb

        /*
         * syscall_wrapper: emulate syscall instruction
         *   prohibited in e.g. Linux-SGX PAL which raises a SIGILL exception
         * See illegal_upcall() @ shim_signal.c and
         *     fixup_child_context() @ shim_clone.c
         *
         * input:
         * %rcx: Instruction address to continue app execution after trapped
         *       syscall instruction
         * %r11: rflags on entering syscall
         */
syscall_wrapper:
        .cfi_startproc
        .cfi_def_cfa %rsp, 0
        # %rcx is used as input for returning %rip
        .cfi_register %rip, %rcx
        # %r11 is used as input to keep %rflags
        .cfi_register %rflags, %r11
        subq $RED_ZONE_SIZE, %rsp
        .cfi_adjust_cfa_offset RED_ZONE_SIZE
        callq *syscalldb@GOTPCREL(%rip)
syscall_wrapper_after_syscalldb:
        addq $RED_ZONE_SIZE, %rsp
        .cfi_adjust_cfa_offset -RED_ZONE_SIZE
        # restore %rflags for syscall abi compatibility.
        # This must be done after "addq $RED_ZONE_SIZE, %rsp" above
        # which destroys %rflags
        xchg %r11, (%rsp)
        .cfi_offset %rflags, 0
        popfq
        .cfi_adjust_cfa_offset -8
        .cfi_same_value %rflags
        pushq %r11
        .cfi_adjust_cfa_offset 8
        jmp *%rcx

        .cfi_endproc
        .size syscall_wrapper, .-syscall_wrapper
