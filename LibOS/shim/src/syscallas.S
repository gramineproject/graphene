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

#include "asm-offsets.h"

        .global syscalldb
        .type syscalldb, @function
        .extern shim_table, debug_unsupp

        .global __syscallas_signal_allowed_0_begin
        .global __syscallas_signal_allowed_0_end
        .global __syscallas_signal_allowed_1_begin
        .global __syscallas_signal_allowed_1_end
        .global __syscallas_signal_allowed_2_begin
        .global __syscallas_signal_allowed_2_end
        .global __syscallas_need_emulate_jmp
        .type __syscallas_signal_allowed_0_begin, @object
        .type __syscallas_signal_allowed_0_end, @object
        .type __syscallas_signal_allowed_1_begin, @object
        .type __syscallas_signal_allowed_1_end, @object
        .type __syscallas_signal_allowed_2_begin, @object
        .type __syscallas_signal_allowed_2_end, @object
        .type __syscallas_need_emulate_jmp, @object

.macro CLEAR_SAVED_AREA_IN_SHIM_TLS
        movq $0, %fs:(SHIM_TCB_OFFSET + TCB_SYSCALL_NR)
        movq $0, %fs:(SHIM_TCB_OFFSET + TCB_SP)
        movq $0, %fs:(SHIM_TCB_OFFSET + TCB_RET_IP)
        movq $0, %fs:(SHIM_TCB_OFFSET + TCB_REGS)
.endm

.macro CHECK_SIGNAL_PENDING_BIT
        lock btrq $SHIM_FLAG_SIGPENDING, %fs:(SHIM_TCB_OFFSET + TCB_FLAGS)
.endm

/* TODO: fix to use CHECK_SIGNAL_PENDING_BIT */
.macro CHECK_SIGNAL_PENDING
        movq %fs:(SHIM_TCB_OFFSET + TCB_TP), %rbx
        addq $THREAD_HAS_SIGNAL, %rbx
        movq (%rbx), %rcx
        cmp $0, %rcx
.endm

syscalldb:
        .cfi_startproc

__syscallas_signal_allowed_0_begin:
        # DEP 7/9/12: Push a stack pointer so clone can find the return address
        pushq %rbp
        .cfi_def_cfa_offset 16
        movq %rsp, %rbp
        .cfi_offset 6,-16
        .cfi_def_cfa_register 6

        pushq %rbx

        cmp $LIBOS_SYSCALL_BOUND, %rax
        jae isundef

        leaq shim_table(%rip), %rbx
        movq (%rbx,%rax,8), %rbx
        cmp $0, %rbx
        je isundef
__syscallas_signal_allowed_0_end:

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

        movq %rax, %fs:(SHIM_TCB_OFFSET + TCB_SYSCALL_NR)
        leaq 16(%rbp), %rax
        movq %rax, %fs:(SHIM_TCB_OFFSET + TCB_SP)
        movq 8(%rbp), %rax
        movq %rax, %fs:(SHIM_TCB_OFFSET + TCB_RET_IP)
        movq %rsp, %fs:(SHIM_TCB_OFFSET + TCB_REGS)

        /* Translating x86_64 kernel calling convention to user-space
         * calling convention */
        movq %r10, %rcx
        call *%rbx

.Lret_nosignal:
        CHECK_SIGNAL_PENDING
        //CHECK_SIGNAL_PENDING_BIT
__syscallas_signal_allowed_1_begin:
        ja .Lsignal_pending
        //jc .Lsignal_pending

.Lret_signal:
	CLEAR_SAVED_AREA_IN_SHIM_TLS

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

ret:
        popq %rbx
        popq %rbp
        retq

isundef:
#ifdef DEBUG
        mov %rax, %rdi
	call *debug_unsupp@GOTPCREL(%rip)
#endif
        movq $-38, %rax
        jmp ret
__syscallas_signal_allowed_1_end:

.Lsignal_pending:
        /*
         * allocate signal stack frame
         *
         * struct shim_context: 16B align + 8
         *                      sizeof(struct shim_context) = 0x38
         * rip to signal handler: 8 bytes
         * struct sigframe
         *   restorer: 8 bytes
         *   ucontext_t: 16 bytes align
         *   siginfo_t
         * struct _libc_fptstate: 64 bytes align: fpu_xstate_size
         * extended area
         * FP_XSTATE_MAGIC2
         */
#define SIGFRAME_SIZE_SUB       (SIGFRAME_SIZE + FP_XSTATE_MAGIC2_SIZE + 64)
        movq %rsp, %rdi
        subq $SIGFRAME_SIZE_SUB, %rdi
        movq fpu_xstate_size@GOTPCREL(%rip), %rbx
        subq (%rbx), %rdi
        andq $(~15), %rdi
        subq $8, %rdi

        movq %rsp, %r11
        movq %rdi, %rsp
        pushfq
        popq %rsi
        movq %rax, %rdx
        pushq %r11
        call *deliver_signal_on_sysret@GOTPCREL(%rip)
        popq %r11
        cmp $0, %rax
        je .Lsignal_not_delivered
        jmp .Lret_signal

.Lsignal_not_delivered:
        movq %fs:(SHIM_TCB_OFFSET + TCB_SYSCALL_NR), %rax
        movq %r11, %rsp
        jmp .Lret_nosignal

        .cfi_endproc
        .size syscalldb, .-syscalldb

        // void __sigreturn(mcontext_t * uc_mcontext)
        .global __sigreturn
        .type __sigreturn, @function
__sigreturn:
        CHECK_SIGNAL_PENDING_BIT
        jnc .Lno_more_signal
	retq

__syscallas_signal_allowed_2_begin:
.Lno_more_signal:
	CLEAR_SAVED_AREA_IN_SHIM_TLS

        movq %rdi, %rsp

        // pop up gregs_t
        popq %r8
        popq %r9
        popq %r10
        popq %r11
        popq %r12
        popq %r13
        popq %r14
        popq %r15
        popq %rdi
        popq %rsi
        popq %rbp
        popq %rbx
        popq %rdx

        movq 2 * 8(%rsp), %rcx  // saved %rsp
        movq 3 * 8(%rsp), %rax  // saved %rip
        movq %rax, -128-8(%rcx) // 8 bytes below redzone

        popq %rax
        popq %rcx
        // skip rsp, rip
        addq $(2 * 8), %rsp

        popfq

        /*
         * iretq or sysretq can't be used in user space.
         *
         * The following two instruction needs to be atomic regarding to
         * interrupt by signal delivering.
         * In signal handler in LibOS, if rip == __syscallas_need_emulate_jmp
         * the following jmp instruction is emulated first, and then proceed to
         * signal handling and deliver signal to user.
         *
         * If signal is delivered at __syscallas_need_emulate_jmp,
         * the saved rip at 8 bytes below the redzone is clobbered.
         */
        movq -3 * 8(%rsp), %rsp
__syscallas_need_emulate_jmp:
        jmp *-128-8(%rsp)
__syscallas_signal_allowed_2_end:
