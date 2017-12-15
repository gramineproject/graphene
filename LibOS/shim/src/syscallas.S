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

        .global syscalldb
        .type syscalldb, @function
        .extern shim_table, debug_unsupp


syscalldb:
        .cfi_startproc

        # DEP 7/9/12: Push a stack pointer so clone can find the return address
        pushq %rbp
        .cfi_def_cfa_offset 16
        movq %rsp, %rbp
        .cfi_offset 6,-16
        .cfi_def_cfa_register 6

        pushq %rbx

        cmp $LIBOS_SYSCALL_BOUND, %rax
        jae isundef

        movq shim_table@GOTPCREL(%rip), %rbx
        movq (%rbx,%rax,8), %rbx
        cmp $0, %rbx
        je isundef

isdef:
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

        movq %rax, %fs:(SHIM_TCB_OFFSET + 24)
        leaq 16(%rbp), %rax
        movq %rax, %fs:(SHIM_TCB_OFFSET + 32)
        movq 8(%rbp), %rax
        movq %rax, %fs:(SHIM_TCB_OFFSET + 40)
        movq %rsp, %fs:(SHIM_TCB_OFFSET + 48)

        /* Translating x86_64 kernel calling convention to user-space
         * calling convention */
        movq %r10, %rcx
        call *%rbx

        movq $0, %fs:(SHIM_TCB_OFFSET + 24)
        movq $0, %fs:(SHIM_TCB_OFFSET + 32)
        movq $0, %fs:(SHIM_TCB_OFFSET + 40)
        movq $0, %fs:(SHIM_TCB_OFFSET + 48)

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

        jmp ret

isundef:
#ifdef DEBUG
        mov %rax, %rdi
        movq debug_unsupp@GOTPCREL(%rip), %rbx
        call *%rbx
#endif
        movq $-38, %rax

ret:
        popq %rbx
        popq %rbp
        retq

        .cfi_endproc
        .size syscalldb, .-syscalldb


        /*
         * syscall_wrapper served as a redirection point
         * for static system calls captured through
         * host-lvel exception handling. Its jobs are:
         * (1) reserving red zone (128 bytes)
         * (2) call syscalldb
         * (3) return to the original code (saved in RBX)
         *
         * Chia-Che 12/13/17:
         * There is a risk that this code may corrupt RBX.
         * I haven't figure out how to preserve RBX because
         * the code needs to sacrifice a register to do
         * the final jump.
         */

        .global syscall_wrapper
        .type syscall_wrapper, @function

syscall_wrapper:
        .cfi_startproc

        /* when calling this, the original RIP is in RBX */
        subq $128, %rsp
        pushq %rbx

        /* now call syscalldb */
        movq syscalldb@GOTPCREL(%rip), %rbx
        callq *%rbx

        /* resume the stack and return to original RIP */
        popq %rbx
        addq $128, %rsp
        jmpq *%rbx

        .cfi_endproc
        .size syscall_wrapper, .-syscall_wrapper
