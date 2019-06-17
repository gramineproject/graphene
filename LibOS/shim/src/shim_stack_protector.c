/* Copyright 2019 Intel Corporation.
   Copyright 2019 Isaku Yamahata <isaku.yamahata at intel com>
                                 <isaku.yamahata at gmail com>
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
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <shim_internal.h>
#include <shim_thread.h>
#include <shim_tls.h>

#include "asm-offsets.h"

noreturn void __shim_init (int argc, void * args)
{
    static uint64_t tcb[STACK_PROTECTOR_CANARY + 8 / sizeof(uint64_t)] =
        { [STACK_PROTECTOR_CANARY / sizeof(uint64_t)] = STACK_PROTECTOR_CANARY_DEFAULT };
    DkSegmentRegister(PAL_SEGMENT_FS, &tcb);
    shim_init(argc, args);
}

static void reset_stack_protector_canary (shim_tcb_t * tcb)
{
    uint64_t stack_protector_canary;
    int ret = DkRandomBitsRead(&stack_protector_canary, sizeof(stack_protector_canary));
    if (ret < 0)
        stack_protector_canary = STACK_PROTECTOR_CANARY_DEFAULT;
    tcb->stack_protector_canary = stack_protector_canary;
}

void init_tcb (shim_tcb_t * tcb)
{
    __init_tcb(tcb);
    reset_stack_protector_canary(tcb);
}

/* This function is used to allocate tls before interpreter start running */
void allocate_tls (__libc_tcb_t * tcb, bool user, struct shim_thread * thread)
{
    __allocate_tls(tcb, user, thread);
    reset_stack_protector_canary(&tcb->shim_tcb);
}
