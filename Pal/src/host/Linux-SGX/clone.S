/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * clone-x86_64.S
 *
 * This file contains architecture-specific implementation of clone
 * method.
 * The source code is imported and modified from the GNU C Library.
 */

/* clone() is even more special than fork() as it mucks with stacks
   and invokes a function in the right context after its all over.  */

#include <asm/unistd.h>
#include <asm/errno.h>

#include "sysdep-arch.h"

#define CLONE_VM	0x00000100
#define CLONE_THREAD	0x00010000

/* The userland implementation is:
   int clone (int (*fn)(void *arg), void *child_stack, int flags, void *arg),
   the kernel entry is:
   int clone (long flags, void *child_stack).

   The parameters are passed in register and on the stack from userland:
   rdi:	fn
   rsi:	child_stack
   rdx:	flags
   rcx:	arg
   r8:	TID field in parent
   r9:	thread pointer
   esp+8: TID field in child

   The kernel expects:
   rax: system call number
   rdi: flags
   rsi: child_stack
   rdx: TID field in parent
   r10: TID field in child
   r8:	thread pointer  */


        .text
ENTRY (clone)
	/* Sanity check arguments.  */
	movq	$-EINVAL, %rax
	testq	%rdi, %rdi		/* no NULL function pointers */
	/* jz	SYSCALL_ERROR_LABEL */
	testq	%rsi, %rsi		/* no NULL stack pointers */
	/* jz	SYSCALL_ERROR_LABEL */

	/* Insert the argument onto the new stack.  */
	subq	$16, %rsi
	movq	%rcx, 8(%rsi)

	/* Save the function pointer.  It will be popped off in the
	   child in the ebx frobbing below.  */
	movq	%rdi, 0(%rsi)

	/* Do the system call.  */
	movq	%rdx, %rdi
	movq	%r8, %rdx
	movq	%r9, %r8
	movq	8(%rsp), %r10
	movl	$SYS_ify(clone), %eax

	/* End FDE now, because in the child the unwind info will be
	   wrong.  */
	cfi_endproc
	syscall

	testq	%rax, %rax
	/* jl	SYSCALL_ERROR_LABEL */
	jz	thread_start
	ret

ENTRY (thread_start)
	cfi_startproc
	/* Clearing frame pointer is insufficient, use CFI.  */
	cfi_undefined (rip)
	/* Clear the frame pointer.  The ABI suggests this be done, to mark
	   the outermost frame obviously.  */
	xorl	%ebp, %ebp

	/* Set up arguments for the function call.  */
	popq	%rax		/* Function to call.  */
	popq	%rdi		/* Argument.  */
	call	*%rax
	/* Call exit with return value from function call. */
	/* movq %rax, %rdi */
	/* movl $SYS_ify(exit), %eax */
	/* syscall */
	/* Instead of syscall exit, let's call thread_exit */
	call thread_exit
	cfi_endproc

	cfi_startproc
END (clone)
