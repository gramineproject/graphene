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
