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

        movq %rsp, %r11
        .cfi_def_cfa_register %r11
        .cfi_register %rsp, %r11
        .cfi_undefined %r11

        # switch stack
        movq %gs:(SHIM_TCB_OFFSET + SHIM_TCB_SYSCALL_STACK), %rsp

        # Create shim_regs struct on the stack.
        pushq %r11              # save old %rsp

        pushq (%r11)            # copy return address from original stack
        .cfi_def_cfa %rsp, 8
        .cfi_val_offset %rsp, 8

syscalldb_from_wrapper:
        pushfq
        .cfi_adjust_cfa_offset 8
        .cfi_val_offset %rflags, -2 * 8

        # Under GDB, single-stepping sets Trap Flag (TP) of EFLAGS,
        # thus TP=1 is stored on pushfq above. Upon consequent popfq,
        # TP is 1, resulting in spurious trap. Reset TP here.
        andq $~0x100, (%rsp)

        cld
        pushq %rbp
        .cfi_adjust_cfa_offset 8
        .cfi_val_offset %rbp, -3 * 8
        pushq %rbx
        .cfi_adjust_cfa_offset 8
        .cfi_val_offset %rbx, -4 * 8
        pushq %rdi
        .cfi_adjust_cfa_offset 8
        .cfi_val_offset %rdi, -5 * 8
        pushq %rsi
        .cfi_adjust_cfa_offset 8
        .cfi_val_offset %rsi, -6 * 8
        pushq %rdx
        .cfi_adjust_cfa_offset 8
        .cfi_val_offset %rdx, -7 * 8
        pushq %rcx
        .cfi_adjust_cfa_offset 8
        .cfi_val_offset %rcx, -8 * 8
        pushq %r8
        .cfi_adjust_cfa_offset 8
        .cfi_val_offset %r8, -9 * 8
        pushq %r9
        .cfi_adjust_cfa_offset 8
        .cfi_val_offset %r9, -10 * 8
        pushq %r10
        .cfi_adjust_cfa_offset 8
        .cfi_val_offset %r10, -11 * 8
        pushq %r11
        .cfi_adjust_cfa_offset 8
        .cfi_val_offset %r11, -12 * 8
        pushq %r12
        .cfi_adjust_cfa_offset 8
        .cfi_val_offset %r12, -13 * 8
        pushq %r13
        .cfi_adjust_cfa_offset 8
        .cfi_val_offset %r13, -14 * 8
        pushq %r14
        .cfi_adjust_cfa_offset 8
        .cfi_val_offset %r14, -15 * 8
        pushq %r15
        .cfi_adjust_cfa_offset 8
        .cfi_val_offset %r15, -16 * 8
        pushq %rax
        .cfi_adjust_cfa_offset 8
        .cfi_val_offset %rax, -17 * 8
        # shim_regs struct ends here.

        movq %rsp, %rbp
        .cfi_def_cfa_register %rbp

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
        .cfi_def_cfa_register %rsp
        addq $2 * 8, %rsp   # skip orig_rax and rsp
        .cfi_adjust_cfa_offset -2 * 8
        popq %r15
        .cfi_restore %r15
        .cfi_adjust_cfa_offset -8
        popq %r14
        .cfi_restore %r14
        .cfi_adjust_cfa_offset -8
        popq %r13
        .cfi_restore %r13
        .cfi_adjust_cfa_offset -8
        popq %r12
        .cfi_restore %r12
        .cfi_adjust_cfa_offset -8
        addq $8, %rsp           # skip %r11 as it's used below
        .cfi_adjust_cfa_offset -8
        popq %r10
        .cfi_restore %r10
        .cfi_adjust_cfa_offset -8
        popq %r9
        .cfi_restore %r9
        .cfi_adjust_cfa_offset -8
        popq %r8
        .cfi_restore %r8
        .cfi_adjust_cfa_offset -8
        popq %rcx
        .cfi_restore %rcx
        .cfi_adjust_cfa_offset -8
        popq %rdx
        .cfi_restore %rdx
        .cfi_adjust_cfa_offset -8
        popq %rsi
        .cfi_restore %rsi
        .cfi_adjust_cfa_offset -8
        popq %rdi
        .cfi_restore %rdi
        .cfi_adjust_cfa_offset -8
        popq %rbx
        .cfi_restore %rbx
        .cfi_adjust_cfa_offset -8
        popq %rbp
        .cfi_restore %rbp
        .cfi_adjust_cfa_offset -8
        popfq
        .cfi_restore %rflags
        .cfi_adjust_cfa_offset -8

        popq %r11
        .cfi_restore %rip, %r11
        .cfi_adjust_cfa_offset -8

        # restore application stack
        popq %rsp
        .cfi_def_cfa %rsp, 8

        jmp *%r11

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
         *   This switches stack to dedicated one allocated by LibOS to avoid
         *   small application stack. e.g. as goroutine.
         * See illegal_upcall() @ shim_signal.c and
         *     fixup_child_context() @ shim_clone.c
         *
         * input:
         * %rcx: Instruction address to continue app execution after trapped
         *       syscall instruction
         * %r11: rflags on entering syscall: unused as %rflags is preserved
         */
syscall_wrapper:
        .cfi_startproc
        .cfi_def_cfa %rsp, 0
        # %rcx is used as input for returning %rip
        .cfi_register %rip, %rcx
        .cfi_register %rflags, %rcx
        # %r11(saved %rflags) isn't needed,
        # so re-use %r11 to store application stack
        movq %rsp, %r11
        .cfi_def_cfa_register %r11
        .cfi_register %rsp, %r11
        .cfi_undefined %r11
        # switch stack to the one allocated by LibOS
        movq %gs:(SHIM_TCB_OFFSET + SHIM_TCB_SYSCALL_STACK), %rsp
        pushq %r11
        pushq %rcx
        jmp syscalldb_from_wrapper
        # no return from syscall_db_from_wrapper

        .cfi_endproc
        .size syscall_wrapper, .-syscall_wrapper
