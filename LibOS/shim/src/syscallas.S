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

#include <shim_tls.h>
#include <shim_unistd_defs.h>

#include "asm-offsets.h"

        .global syscalldb
        .type syscalldb, @function
        .extern shim_table, debug_unsupp
        .global syscall_wrapper
        .type syscall_wrapper, @function


syscalldb:
        .cfi_startproc

        # Create shim_regs struct on the stack.
        pushfq
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
        # shim_regs struct ends here.

        movq %rsp, %rbp
        .cfi_def_cfa_offset SHIM_REGS_SIZE+8  # +8 for ret_addr
        .cfi_offset %rbp, -3 * 8    # saved_rbp is at CFA-24 (ret + saved_rflags + saved_rbp)
        .cfi_def_cfa_register %rbp  # %rbp

        cmp $LIBOS_SYSCALL_BOUND, %rax
        jae isundef

        movq shim_table@GOTPCREL(%rip), %rbx
        movq (%rbx,%rax,8), %rbx
        cmp $0, %rbx
        je isundef

        movq %rax, %fs:(SHIM_TCB_OFFSET + TCB_SYSCALL_NR)
        leaq SHIM_REGS_SIZE+8(%rbp), %rax
        movq %rax, %fs:(SHIM_TCB_OFFSET + TCB_SP)
        movq SHIM_REGS_SIZE(%rbp), %rax
        movq %rax, %fs:(SHIM_TCB_OFFSET + TCB_RET_IP)
        movq %rbp, %fs:(SHIM_TCB_OFFSET + TCB_REGS)

        /* Translating x86_64 kernel calling convention to user-space
         * calling convention */
        movq %r10, %rcx
        andq $~0xF, %rsp  # Required by System V AMD64 ABI.
        call *%rbx

        movq $0, %fs:(SHIM_TCB_OFFSET + TCB_SYSCALL_NR)
        movq $0, %fs:(SHIM_TCB_OFFSET + TCB_SP)
        movq $0, %fs:(SHIM_TCB_OFFSET + TCB_RET_IP)
        movq $0, %fs:(SHIM_TCB_OFFSET + TCB_REGS)

ret:
        movq %rbp, %rsp
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
        popfq
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
         *
         * input:
         * %rcx: Instruction address to continue app execution after trapped
         *       syscall instruction
         * %r11: rflags on entering syscall
         *
         * FIXME: preserve rflags.
         *        remember that clone-child can't use parent stack.
         */
syscall_wrapper:
        .cfi_startproc

        subq $RED_ZONE_SIZE, %rsp
        callq *syscalldb@GOTPCREL(%rip)
        addq $RED_ZONE_SIZE, %rsp
#if 0
        # TODO: once clone emulation is fixed, remove this #if 0
        xchg %r11, (%rsp)
        popfq
        pushq %r11
#endif
        jmp *%rcx

        .cfi_endproc
        .size syscall_wrapper, .-syscall_wrapper
