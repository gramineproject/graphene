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

#include "sysdep-arch.h"

static inline int pal_set_tcb(PAL_TCB* tcb) {
    return INLINE_SYSCALL(arch_prctl, 2, ARCH_SET_GS, tcb);
}

#endif /* IN_PAL */

#endif /* __LINUX_X86_64_PAL_HOST_ARCH_H__ */
