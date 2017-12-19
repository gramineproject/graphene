/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

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

/* This file is imported and modified from the GNU C Library */

/* This file was copied directly from the Linux implementation and modified to work on FreeBSD.
    It may contain a lot of unnecessary code. */
#ifndef _LINUX_X86_64_SYSDEP_H
#define _LINUX_X86_64_SYSDEP_H 1

#include <sysdeps/generic/sysdep.h>
#include <sys/syscall.h>

/* BSD useds SYS_* sys call names, so we can use these to map syscall names to syscall numbers from syscall.h */
#define SYS_ifyBSD(syscall_name) SYS_##syscall_name

#ifdef __ASSEMBLER__

/* ELF uses byte-counts for .align, most others use log2 of count of bytes.  */
#define ALIGNARG(log2) 1<<log2
#define ASM_GLOBAL_DIRECTIVE .global
/* For ELF we need the `.type' directive to make shared libs work right.  */
#define ASM_TYPE_DIRECTIVE(name,typearg) .type name,typearg;
#define ASM_SIZE_DIRECTIVE(name) .size name,.-name;

/* Define an entry point visible from C.  */
#define ENTRY(name)                                            \
  ASM_GLOBAL_DIRECTIVE name;                                   \
  ASM_TYPE_DIRECTIVE (name,@function)                          \
  .align ALIGNARG(4);                                          \
  name:                                                        \
  cfi_startproc;

#undef  END
#define END(name)                                              \
  cfi_endproc;                                                 \
  ASM_SIZE_DIRECTIVE(name)

#undef  DO_CALL
#define DO_CALL(syscall_name, args)             \
    DOARGS_##args                               \
    movl $SYS_ify (syscall_name), %eax;         \
    syscall;

#define DOARGS_0 /* nothing */
#define DOARGS_1 /* nothing */
#define DOARGS_2 /* nothing */
#define DOARGS_3 /* nothing */
#define DOARGS_4 movq %rcx, %r10;
#define DOARGS_5 DOARGS_4
#define DOARGS_6 DOARGS_5

#else    /* !__ASSEMBLER__ */
/* Define a macro which expands inline into the wrapper code for a system
   call.  */
#undef INLINE_SYSCALL

#define INLINE_SYSCALL(name, nr, args...) INTERNAL_SYSCALL(name, , nr, args)

#undef INTERNAL_SYSCALL_DECL
#define INTERNAL_SYSCALL_DECL(err) do { } while (0)

#define INTERNAL_SYSCALL_NCS(name, err, nr, args...)    \
  ({                                                    \
    LOAD_ARGS_##nr (args)                               \
    LOAD_REGS_##nr                                      \
    unsigned long resultvar;                            \
    asm volatile (                                      \
    "int $0x80\n\t"                                     \
    : "=a" (resultvar)                                  \
    : "0" (name) ASM_ARGS_##nr                          \
    : "memory", "cc");                                  \
    (long) IS_SYSCALL_ERROR(resultvar);                 \
   })

#undef INTERNAL_SYSCALL
#define INTERNAL_SYSCALL(name, err, nr, args...)        \
INTERNAL_SYSCALL_NCS(SYS_ifyBSD(name), err, nr, ##args)

#undef INTERNAL_SYSCALL_ERROR
#define INTERNAL_SYSCALL_ERROR(val) ((val) < 0)

#undef INTERNAL_SYSCALL_ERROR_P
#define INTERNAL_SYSCALL_ERROR_P(val) \
  ((unsigned long) (val) >= -4095L)

#undef INTERNAL_SYSCALL_ERRNO
#define INTERNAL_SYSCALL_ERRNO(val) (-(val))

#undef INTERNAL_SYSCALL_ERRNO_P
#define INTERNAL_SYSCALL_ERRNO_P(val) (-((long) val))

/*
If a syscall fails, it generally sets the carry flag and returns the error code in rax. 
To simplify matters and reuse a lot of the Linux code, we change rax to negative after checking the carry flag.
*/

#define IS_SYSCALL_ERROR(val)                       \
    ({                                              \
    int carry;                                      \
    asm volatile("mov $0, %0\n\t"                   \
          "adc $0, %0\n\t"                          \
          : "=b"(carry)                             \
          :                                         \
          : "cc", "memory", "eax");                 \
     (carry) ? -val : val; })

#define LOAD_ARGS_0()
#define LOAD_REGS_0
#define ASM_ARGS_0

#define LOAD_ARGS_1(a1)                             \
  long int __arg1 = (long) (a1);                    \
  LOAD_ARGS_0 ()
#define LOAD_REGS_1                                 \
  register long int _a1 asm ("rdi") = __arg1;       \
  LOAD_REGS_0

#define ASM_ARGS_1    ASM_ARGS_0, "r" (_a1)

#define LOAD_ARGS_2(a1, a2)                         \
  long int __arg2 = (long) (a2);                    \
  LOAD_ARGS_1 (a1)
#define LOAD_REGS_2                                 \
  register long int _a2 asm ("rsi") = __arg2;       \
  LOAD_REGS_1
#define ASM_ARGS_2    ASM_ARGS_1, "r" (_a2)

#define LOAD_ARGS_3(a1, a2, a3)                     \
  long int __arg3 = (long) (a3);                    \
  LOAD_ARGS_2 (a1, a2)
#define LOAD_REGS_3                                 \
  register long int _a3 asm ("rdx") = __arg3;       \
  LOAD_REGS_2

#define ASM_ARGS_3    ASM_ARGS_2, "r" (_a3)

#define LOAD_ARGS_4(a1, a2, a3, a4)                 \
  long int __arg4 = (long) (a4);                    \
  LOAD_ARGS_3 (a1, a2, a3)
#define LOAD_REGS_4                                 \
  register long int _a4 asm ("rcx") = __arg4;       \
  LOAD_REGS_3
#define ASM_ARGS_4    ASM_ARGS_3, "r" (_a4)

#define LOAD_ARGS_5(a1, a2, a3, a4, a5)             \
  long int __arg5 = (long) (a5);                    \
  LOAD_ARGS_4 (a1, a2, a3, a4)
#define LOAD_REGS_5                                 \
  register long int _a5 asm ("r8") = __arg5;        \
  LOAD_REGS_4
#define ASM_ARGS_5    ASM_ARGS_4, "r" (_a5)

#define LOAD_ARGS_6(a1, a2, a3, a4, a5, a6)         \
  long int __arg6 = (long) (a6);                    \
  LOAD_ARGS_5 (a1, a2, a3, a4, a5)
#define LOAD_REGS_6                                 \
register long int _a6 asm ("r9") = __arg6;          \
  LOAD_REGS_5
#define ASM_ARGS_6    ASM_ARGS_5, "r" (_a6)

#endif    /* __ASSEMBLER__ */

#endif /* linux/x86_64/sysdep.h */
