/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#define __ASSEMBLY__
#include <asm/unistd.h>

.global do_syscall
.type do_syscall, @function
.align 0x10
do_syscall:
    .cfi_startproc
    mov %rdi, %rax
    mov %rsi, %rdi
    mov %rdx, %rsi
    mov %rcx, %rdx
    mov %r8, %r10
    mov %r9, %r8
    mov 8(%rsp), %r9
    syscall
    ret
    .cfi_endproc

.global clone
.type clone, @function
.align 0x10
/* C declaration has type:
 * long clone(int (*f)(void*),          // rdi
 *            void* stack,              // rsi
 *            int flags,                // rdx
 *            void* arg,                // rcx
 *            void* parent_tid,         // r8
 *            void* tls,                // r9
 *            void* child_tid,          // [rsp + 8]
 *            void (*exit_func)(int)    // [rsp + 0x10]
 * );
 */
clone:
    .cfi_startproc
    /* Pass functions and argument on the child stack. */
    sub $0x18, %rsi
    mov %rdi, (%rsi)
    mov %rcx, 8(%rsi)
    mov 0x10(%rsp), %rdi
    mov %rdi, 0x10(%rsi)

    mov %rdx, %rdi      /* flags */
    /* %rsi already holds stack */
    mov %r8, %rdx       /* parent_tid */
    mov 8(%rsp), %r10   /* child_tid */
    mov %r9, %r8        /* tls */
    mov $__NR_clone, %eax
    syscall

    test %rax, %rax
    je .Lchild
    ret

.Lchild:
    .cfi_undefined %rip
    .cfi_undefined %rbp
    xor %ebp, %ebp
    pop %rax
    pop %rdi
    pop %rbx
    call *%rax
    mov %rax, %rdi
    call *%rbx
    /* Unreachable. */
    ud2
    .cfi_endproc

.global vfork
.type vfork, @function
.align 0x10
vfork:
    .cfi_startproc
    pop %rdx
    .cfi_register %rip, %rdx
    mov $__NR_vfork, %eax
    syscall
    jmp *%rdx
    .cfi_endproc
