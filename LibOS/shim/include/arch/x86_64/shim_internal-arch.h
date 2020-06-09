/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * shim_internal-arch.h
 */

#ifndef _SHIM_INTERNAL_ARCH_H_
#define _SHIM_INTERNAL_ARCH_H_

#define __SWITCH_STACK(stack_top, func, arg)                    \
    do {                                                        \
        /* 16 Bytes align of stack */                           \
        uintptr_t __stack_top = (uintptr_t)(stack_top);         \
        __stack_top &= ~0xf;                                    \
        __stack_top -= 8;                                       \
        __asm__ volatile (                                      \
            "movq %0, %%rbp\n"                                  \
            "movq %0, %%rsp\n"                                  \
            "jmpq *%1\n"                                        \
            ::"r"(__stack_top), "r"(func), "D"(arg): "memory"); \
    } while (0)

static_always_inline void* current_stack(void) {
    void* _rsp;
    __asm__ volatile ("movq %%rsp, %0" : "=r"(_rsp) :: "memory");
    return _rsp;
}

#endif /* _SHIM_INTERNAL_ARCH_H_ */
