/* Copyright (C) 2014 OSCAR lab, Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * syscallas.S
 *
 * This file contains the entry point of system call table in library OS.
 */

#include <shim_tls.h>

.text
        .global syscalldb
        .type syscalldb, @function
        .extern shim_table

syscalldb:
        .cfi_startproc

        # avoid red zone for previous rsp
        subq $128, %rsp
        .cfi_def_cfa_offset 136

        # DEP 7/9/12: Push a stack pointer so clone can find the return address
        pushq %rbp
        .cfi_def_cfa_offset 144
        movq %rsp, %rbp
        .cfi_offset 6,-144
        .cfi_def_cfa_register 6

        pushq %rbx

        leaq shim_table(%rip), %rbx
        movq (%rbx,%rax,8), %rbx
        cmp $0, (%rbx)
        je isundef

isdef:
        pushq %rdi
        pushq %rsi
        pushq %rdx
        pushq %rcx
        pushq %r8
        pushq %r9
        pushq %r12
        pushq %r13
        pushq %r14
        pushq %r15

        movq %rax, %fs:(SHIM_TCB_OFFSET + 24)
        leaq 232(%rsp), %rax
        movq %rax, %fs:(SHIM_TCB_OFFSET + 32)
        movq -8(%rax), %rax
        movq %rax, %fs:(SHIM_TCB_OFFSET + 40)
        movq %rsp, %fs:(SHIM_TCB_OFFSET + 48)

        call *%rbx

        movq $0, %fs:(SHIM_TCB_OFFSET + 24)
        movq $0, %fs:(SHIM_TCB_OFFSET + 32)
        movq $0, %fs:(SHIM_TCB_OFFSET + 40)
        movq $0, %fs:(SHIM_TCB_OFFSET + 48)

        popq %r15
        popq %r14
        popq %r13
        popq %r12
        popq %r9
        popq %r8
        popq %rcx
        popq %rdx
        popq %rsi
        popq %rdi

        jmp ret

isundef:
        movq $-38, %rax

ret:
        popq %rbx
        popq %rbp
        addq $128, %rsp
        retq

        .cfi_endproc
        .size syscalldb, .-syscalldb
