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
 * gettimeofday-x86_64.S
 *
 * This file contains architecture-specific implementation of timing
 * method.
 * The source code is imported and modified from the GNU C Library.
 */

#include <asm/unistd.h>

#include "sysdep-x86_64.h"

/* For the calculation see asm/vsyscall.h.  */
#define VSYSCALL_ADDR_vgettimeofday	0xffffffffff600000

        .text
ENTRY (gettimeofday)
	/* Align stack.  */
	sub	$0x8, %rsp
	cfi_adjust_cfa_offset(8)
	movq	$VSYSCALL_ADDR_vgettimeofday, %rax
	callq	*%rax
	/* Check error return.  */
	/* cmpl	$-4095, %eax */
	/* jae	SYSCALL_ERROR_LABEL */

pseudo_end:
	add	$0x8, %rsp
	cfi_adjust_cfa_offset(-8)
	ret
END(gettimeofday)
