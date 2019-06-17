/* Copyright 2019 Intel Corporation.
 * Copyright 2019 Isaku Yamahata <isaku.yamahata at intel com>
 *                                <isaku.yamahata at gmail com>
 * This file is part of Graphene Library OS.
 *
 * Graphene Library OS is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * Graphene Library OS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "pal_linux.h"
#include "pal_internal.h"

#include <linux/signal.h>
#include <asm/prctl.h>

#ifdef ENABLE_STACK_PROTECTOR
/* At the begining of entry point, rsp starts at argc, then argvs,
   envps and auxvs. Here we store rsp to rdi, so it will not be
   messed up by function calls */
__asm__ (
    ".global pal_start \n"
    ".type pal_start,@function \n"
    "pal_start: \n"
    "  movq %rsp, %rdi \n"
    "  call __pal_linux_main \n");

void __pal_linux_main (void * args)
{
    static PAL_TCB tcb = {
        .stack_protector_canary = STACK_PROTECTOR_CANARY_DEFAULT
    };

    int ret = INLINE_SYSCALL(arch_prctl, 2, ARCH_SET_GS, &tcb);
    if (IS_ERR(ret)) {
        while (true) {
            /* do nothing */
        }
    }
    pal_linux_main(args);
}
#endif

/*
 * pal_thread_init(): An initialization wrapper of a newly-created thread (including
 * the first thread). This function accepts a TCB pointer to be set to the GS register
 * of the thread. The rest of the TCB is used as the alternative stack for signal
 * handling.
 */
int pal_thread_init (void * tcbptr)
{
    PAL_TCB * tcb = tcbptr;
    int ret;

    ret = INLINE_SYSCALL(arch_prctl, 2, ARCH_SET_GS, tcb);
    if (IS_ERR(ret))
        return -ERRNO(ret);

    if (tcb->alt_stack) {
        // Align stack to 16 bytes
        void * alt_stack_top = (void *) ((uint64_t) tcb & ~15);
        assert(alt_stack_top > tcb->alt_stack);
        stack_t ss;
        ss.ss_sp    = alt_stack_top;
        ss.ss_flags = 0;
        ss.ss_size  = alt_stack_top - tcb->alt_stack;

        ret = INLINE_SYSCALL(sigaltstack, 2, &ss, NULL);
        if (IS_ERR(ret))
            return -ERRNO(ret);
    }

    if (tcb->callback)
        return (*tcb->callback) (tcb->param);

    return 0;
}
