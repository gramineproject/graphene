/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * This file contains Linux on x86_64 specific functions related to the PAL.
 */

#ifndef __LINUX_X86_64_PAL_HOST_ARCH_H__
#define __LINUX_X86_64_PAL_HOST_ARCH_H__

#ifdef IN_PAL

#if defined(__i386__)
#include <asm/ldt.h>
#else
#include <asm/prctl.h>
#endif

#include "api.h"
#include "sysdep-arch.h"

/* Graphene uses GCC's stack protector that looks for canary at gs:[0x8], but this function changes
 * the GS register value, so we disable stack protector here (even though it is mostly inlined) */
__attribute_no_stack_protector
static inline int pal_set_tcb(PAL_TCB* tcb) {
    return INLINE_SYSCALL(arch_prctl, 2, ARCH_SET_GS, tcb);
}

/* Linux PAL is loaded at a random address by the host Linux because of ASLR (approx. at 0x7f...
 * address). The macro below is a max available address for LibOS memory management, chosen to
 * preclude a case when the checkpointed-by-parent memory region overlaps with Linux PAL
 * executable's memory region during restore-by-child. */
#define MMAP_MAX_ADDR 0x555555554000ul

#endif /* IN_PAL */

#endif /* __LINUX_X86_64_PAL_HOST_ARCH_H__ */
