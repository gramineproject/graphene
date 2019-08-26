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

#ifndef _LINUX_X86_64_SYSDEP_H
#define _LINUX_X86_64_SYSDEP_H 1

#include <sysdeps/generic/sysdep.h>

/* For Linux we can use the system call table in the header file
    /usr/include/asm/unistd.h
   of the kernel.  But these symbols do not follow the SYS_* syntax
   so we have to redefine the `SYS_ify' macro here.  */
#undef SYS_ify
#define SYS_ify(syscall_name) __NR_##syscall_name

/* This is a kludge to make syscalls.list find these under the names
   pread and pwrite, since some kernel headers define those names
   and some define the *64 names for the same system calls.  */
#if !defined __NR_pread && defined __NR_pread64
#define __NR_pread __NR_pread64
#endif
#if !defined __NR_pwrite && defined __NR_pwrite64
#define __NR_pwrite __NR_pwrite64
#endif

/* This is to help the old kernel headers where __NR_semtimedop is not
   available.  */
#ifndef __NR_semtimedop
#define __NR_semtimedop 220
#endif

#ifdef __ASSEMBLER__

/* ELF uses byte-counts for .align, most others use log2 of count of bytes.  */
#define ALIGNARG(log2)       (1 << (log2))
#define ASM_GLOBAL_DIRECTIVE .global
/* For ELF we need the `.type' directive to make shared libs work right.  */
#define ASM_TYPE_DIRECTIVE(name, typearg) .type name,typearg;
#define ASM_SIZE_DIRECTIVE(name)          .size name,.-name;

#define C_LABEL(name) name

/* Define an entry point visible from C.  */
#define ENTRY(name)                      \
    ASM_GLOBAL_DIRECTIVE name;           \
    ASM_TYPE_DIRECTIVE(name, @function); \
    .align ALIGNARG(4);                  \
    name:                                \
    cfi_startproc;

#undef END
#define END(name) \
    cfi_endproc;  \
    ASM_SIZE_DIRECTIVE(name)

/* The Linux/x86-64 kernel expects the system call parameters in
   registers according to the following table:

    syscall number    rax
    arg 1        rdi
    arg 2        rsi
    arg 3        rdx
    arg 4        r10
    arg 5        r8
    arg 6        r9

    The Linux kernel uses and destroys internally these registers:
    return address from
    syscall        rcx
    additionally clobbered: r12-r15,rbx,rbp
    eflags from syscall    r11

    Normal function call, including calls to the system call stub
    functions in the libc, get the first six parameters passed in
    registers and the seventh parameter and later on the stack.  The
    register use is as follows:

     system call number    in the DO_CALL macro
     arg 1        rdi
     arg 2        rsi
     arg 3        rdx
     arg 4        rcx
     arg 5        r8
     arg 6        r9

    We have to take care that the stack is aligned to 16 bytes.  When
    called the stack is not aligned since the return address has just
    been pushed.


    Syscalls of more than 6 arguments are not supported.  */

#ifndef DO_SYSCALL
#define DO_SYSCALL syscall
#endif

#undef DO_CALL
#define DO_CALL(syscall_name, args)     \
    DOARGS_##args;                      \
    movl $SYS_ify(syscall_name), %eax;  \
    DO_SYSCALL;

#define DOARGS_0 /* nothing */
#define DOARGS_1 /* nothing */
#define DOARGS_2 /* nothing */
#define DOARGS_3 /* nothing */
#define DOARGS_4 movq %rcx, %r10;
#define DOARGS_5 DOARGS_4
#define DOARGS_6 DOARGS_5

#else /* !__ASSEMBLER__ */
/* Define a macro which expands inline into the wrapper code for a system
   call.  */
#undef INLINE_SYSCALL

#define INLINE_SYSCALL(name, nr, args...) INTERNAL_SYSCALL(name, , nr, args)

#undef INTERNAL_SYSCALL_DECL
#define INTERNAL_SYSCALL_DECL(err) \
    do {                           \
    } while (0)

#ifndef DO_SYSCALL
#define DO_SYSCALL "syscall"
#endif

#define INTERNAL_SYSCALL_NCS(name, err, nr, args...)     \
    ({                                                   \
        unsigned long resultvar;                         \
        LOAD_ARGS_##nr(args);                            \
        LOAD_REGS_##nr;                                  \
        __asm__ volatile(DO_SYSCALL                      \
                         : "=a"(resultvar)               \
                         : "0"(name)ASM_ARGS_##nr        \
                         : "memory", "cc", "r11", "cx"); \
        (long)resultvar;                                 \
    })

#undef INTERNAL_SYSCALL
#define INTERNAL_SYSCALL(name, err, nr, args...) INTERNAL_SYSCALL_NCS(__NR_##name, err, nr, ##args)

#undef INTERNAL_SYSCALL_ERROR
#define INTERNAL_SYSCALL_ERROR(val) ((val) < 0)

#undef INTERNAL_SYSCALL_ERROR_P
#define INTERNAL_SYSCALL_ERROR_P(val) ((unsigned long)(val) >= (unsigned long)-4095L)

#undef INTERNAL_SYSCALL_ERRNO
#define INTERNAL_SYSCALL_ERRNO(val) (-(val))

#undef INTERNAL_SYSCALL_ERRNO_P
#define INTERNAL_SYSCALL_ERRNO_P(val) (-((long)val))

#define LOAD_ARGS_0()
#define LOAD_REGS_0
#define ASM_ARGS_0

#define LOAD_ARGS_1(a1)           \
    long int __arg1 = (long)(a1); \
    LOAD_ARGS_0()
#define LOAD_REGS_1                                \
    register long int _a1 __asm__("rdi") = __arg1; \
    LOAD_REGS_0
#define ASM_ARGS_1 ASM_ARGS_0, "r"(_a1)

#define LOAD_ARGS_2(a1, a2)       \
    long int __arg2 = (long)(a2); \
    LOAD_ARGS_1(a1)
#define LOAD_REGS_2                                \
    register long int _a2 __asm__("rsi") = __arg2; \
    LOAD_REGS_1
#define ASM_ARGS_2 ASM_ARGS_1, "r"(_a2)

#define LOAD_ARGS_3(a1, a2, a3)   \
    long int __arg3 = (long)(a3); \
    LOAD_ARGS_2(a1, a2)
#define LOAD_REGS_3                                \
    register long int _a3 __asm__("rdx") = __arg3; \
    LOAD_REGS_2
#define ASM_ARGS_3 ASM_ARGS_2, "r"(_a3)

#define LOAD_ARGS_4(a1, a2, a3, a4) \
    long int __arg4 = (long)(a4);   \
    LOAD_ARGS_3(a1, a2, a3)
#define LOAD_REGS_4                                \
    register long int _a4 __asm__("r10") = __arg4; \
    LOAD_REGS_3
#define ASM_ARGS_4 ASM_ARGS_3, "r"(_a4)

#define LOAD_ARGS_5(a1, a2, a3, a4, a5) \
    long int __arg5 = (long)(a5);       \
    LOAD_ARGS_4(a1, a2, a3, a4)
#define LOAD_REGS_5                               \
    register long int _a5 __asm__("r8") = __arg5; \
    LOAD_REGS_4
#define ASM_ARGS_5 ASM_ARGS_4, "r"(_a5)

#define LOAD_ARGS_6(a1, a2, a3, a4, a5, a6) \
    long int __arg6 = (long)(a6);           \
    LOAD_ARGS_5(a1, a2, a3, a4, a5)
#define LOAD_REGS_6                               \
    register long int _a6 __asm__("r9") = __arg6; \
    LOAD_REGS_5
#define ASM_ARGS_6 ASM_ARGS_5, "r"(_a6)

#endif /* __ASSEMBLER__ */

#endif /* linux/x86_64/sysdep.h */
