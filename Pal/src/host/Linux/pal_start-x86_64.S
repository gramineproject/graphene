/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * pal_start-x86_64.S
 *
 * This file contains architecture-specific implementation of pal_start.
 */

#include "sysdep-arch.h"

	.text
ENTRY(pal_start)
	movq  %rsp, %rdi /* 1st arg for pal_linux_main: initial RSP */
	movq  %rdx, %rsi /* 2nd arg: fini callback */
	xorq  %rbp, %rbp /* mark the last stack frame with RBP == 0 (for debuggers) */
	andq  $~15, %rsp
	call  pal_linux_main
