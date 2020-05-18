/*
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
