/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef _SHIM_INTERNAL_ARCH_H_
#define _SHIM_INTERNAL_ARCH_H_

#define __SWITCH_STACK(stack_top, func, arg)                    \
    do {                                                        \
        /* 16 Bytes align of stack */                           \
        uintptr_t __stack_top = (uintptr_t)(stack_top);         \
        __stack_top &= ~0xf;                                    \
        __stack_top -= 8;                                       \
        __asm__ volatile (                                      \
            "movq %0, %%rsp\n"                                  \
            "xorq %%rbp, %%rbp\n"                               \
            "jmpq *%%rcx\n"                                     \
            :                                                   \
            : "r"(__stack_top), "c"(func), "D"(arg)             \
            : "memory");                                        \
        __builtin_unreachable();                                \
    } while (0)

#define CALL_ELF_ENTRY(ENTRY, ARGP)      \
    __asm__ volatile(                    \
        "pushq $0\r\n"                   \
        "popfq\r\n"                      \
        "movq %%rbx, %%rsp\r\n"          \
        "jmp *%%rax\r\n"                 \
        :                                \
        : "a"(ENTRY), "b"(ARGP), "d"(0)  \
        : "memory", "cc")

#define SHIM_ELF_HOST_MACHINE EM_X86_64

#endif /* _SHIM_INTERNAL_ARCH_H_ */
