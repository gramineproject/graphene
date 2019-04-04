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

        .global __syscallas_return_begin
        .global __syscallas_return_before_jmp
        .global __syscallas_return_end
        .type __syscallas_return_begin, @function
        .type __syscallas_return_before_jmp, @function
        .type __syscallas_return_end, @function

        .global syscalldb_check_sigpending
        .type syscalldb_check_sigpending, @function

        .global __syscalldb_check_sigpending_begin
        .global __syscalldb_check_sigpending_end
        .type __syscalldb_check_sigpending_begin, @function
        .type __syscalldb_check_sigpending_end, @function

.macro CHECK_SIGNAL_PENDING_BIT
        lock btrq $SHIM_FLAG_SIGPENDING, %gs:(SHIM_TCB_OFFSET + SHIM_TCB_FLAGS)
.endm

syscalldb:
        .cfi_startproc
        .cfi_def_cfa %rsp, 8

        movq %rsp, %r11
        .cfi_def_cfa_register %r11
        .cfi_register %rsp, %r11
        .cfi_undefined %r11

        # switch stack
        movq %gs:(SHIM_TCB_OFFSET + SHIM_TCB_SYSCALL_STACK_HIGH), %rsp

        # Create shim_regs struct on the stack.
        pushq %r11 # save old %rsp
        # saved rsp has to point to the top of the application stack
        # (before call to this stub) so we move it past saved return address
        addq $8, (%rsp)
        .cfi_def_cfa %rsp, 0
        .cfi_offset %rsp, 0

        pushq (%r11) # copy return address from original stack
        .cfi_adjust_cfa_offset 8
        .cfi_offset %rip, -8


.Lsyscalldb_from_wrapper:
        pushfq
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %rflags, 0

        # Under GDB, single-stepping sets Trap Flag (TP) of EFLAGS,
        # thus TP=1 is stored on pushfq above. Upon consequent popfq,
        # TP is 1, resulting in spurious trap. Reset TP here.
        andq $~0x100, (%rsp)

        cld
        pushq %rbp
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %rbp, 0
        pushq %rbx
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %rbx, 0
        pushq %rdi
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %rdi, 0
        pushq %rsi
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %rsi, 0
        pushq %rdx
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %rdx, 0
        pushq %rcx
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %rcx, 0
        pushq %r8
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %r8, 0
        pushq %r9
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %r9, 0
        pushq %r10
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %r10, 0
        pushq %r11
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %r11, 0
        pushq %r12
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %r12, 0
        pushq %r13
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %r13, 0
        pushq %r14
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %r14, 0
        pushq %r15
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %r15, 0
        pushq %rax
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %rax, 0
        # shim_regs struct ends here.

        movq %rsp, %rbp
        .cfi_def_cfa_register %rbp

        cmp $LIBOS_SYSCALL_BOUND, %rax
        jae isundef
        .cfi_remember_state

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
        jmp __syscallas_return_begin

.Ldeliver_signal:
        movq %rax, %rdi # to preverve returning value
        call *deliver_signal_on_sysret@GOTPCREL(%rip)

__syscallas_return_begin:
        CHECK_SIGNAL_PENDING_BIT
        jc .Ldeliver_signal

        movq %rbp, %rsp
        .cfi_def_cfa_register %rsp
        addq $8, %rsp # skip orig_rax
        .cfi_adjust_cfa_offset -8
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
        addq $8, %rsp # skip %r11 as it's used below
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
        .cfi_register %rip, %r11
        .cfi_adjust_cfa_offset -8
        movq %r11, %gs:(SHIM_TCB_OFFSET + SHIM_TCB_TMP_RIP)
        movq SHIM_REGS_R11 - SHIM_REGS_RSP(%rsp), %r11
        .cfi_restore %r11

        # how to specify
        # previous %rip = %gs:(SHIM_TCB_OFFSET + SHIM_TCB_TMP_RIP)?
        .cfi_undefined %rip

        # restore application stack
        popq %rsp
        .cfi_restore %rsp

        movq $0, %gs:(SHIM_TCB_OFFSET + TCB_REGS)

__syscallas_return_before_jmp:
        jmp *%gs:(SHIM_TCB_OFFSET + SHIM_TCB_TMP_RIP)
__syscallas_return_end:

isundef:
        .cfi_restore_state
#ifdef DEBUG
        mov %rax, %rdi
        andq $~0xF, %rsp  # Required by System V AMD64 ABI.
        call *debug_unsupp@GOTPCREL(%rip)
#endif
        movq $-38, %rax  # ENOSYS
        jmp __syscallas_return_begin

        .cfi_endproc
        .size syscalldb, .-syscalldb

        /*
         * syscall_wrapper: emulate syscall instruction
         *   prohibited in e.g. Linux-SGX PAL which raises a SIGILL exception
         *   This switches stack to dedicated one allocated by LibOS to avoid
         *   small application stack. e.g. as goroutine.
         * See illegal_upcall() @ shim_signal.c
         *
         * argument:
         * %rcx: Instruction address to continue app execution after trapped
         *       syscall instruction
         * %r11: rflags on entering syscall: unused as %rflags is preserved
         *
         * also this function can be used to invoke systemcall without
         * consuming application stack. The code snippet looks like
         *     leaq 1f(%rip), %rcx
         *     jmp *syscall_wrapper(%rip)
         *     1:
         */
syscall_wrapper:
        .cfi_startproc
        .cfi_def_cfa %rsp, 0    # we don't have %rip saved on stack.
        # %rcx is used as input for returning %rip
        .cfi_register %rip, %rcx

        # %r11(saved %rflags) isn't needed,
        # so re-use %r11 to store application stack
        movq %rsp, %r11
        .cfi_def_cfa_register %r11
        .cfi_register %rsp, %r11
        .cfi_undefined %r11

        # switch stack to the one allocated by LibOS
        movq %gs:(SHIM_TCB_OFFSET + SHIM_TCB_SYSCALL_STACK_HIGH), %rsp
        pushq %r11
        .cfi_def_cfa %rsp, 0
        .cfi_offset %rsp, 0
        pushq %rcx
        .cfi_adjust_cfa_offset 8
        .cfi_offset %rip, -8
        jmp .Lsyscalldb_from_wrapper

        .cfi_endproc
        .size syscall_wrapper, .-syscall_wrapper

syscalldb_check_sigpending:
        .cfi_startproc
__syscalldb_check_sigpending_begin:
        CHECK_SIGNAL_PENDING_BIT
        jc .Lsigpending
        ret

.Lsigpending:
        # call nop syscall to trigger signal delivery.
        # Any syscall with no side effect is okay.
        # (Or dedicated syscall can be introduced in shim_table.c)
        movq $__NR_gettid, %rax
        jmp syscalldb

__syscalldb_check_sigpending_end:
        .cfi_endproc
        .size syscalldb_check_sigpending, .-syscalldb_check_sigpending
