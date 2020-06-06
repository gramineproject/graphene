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
 * shim_context-x86_64.c
 *
 * This file contains code for x86-specific CPU context manipulation.
 */

#include "shim_context.h"

#include "asm-offsets.h"
#include "shim_internal.h"

void restore_context(struct shim_context* context) {
    assert(context->regs);
    struct shim_regs regs = *context->regs;
    debug("restore context: SP = 0x%08lx, IP = 0x%08lx\n", regs.rsp, regs.rip);

    /* don't clobber redzone. If sigaltstack is used,
     * this area won't be clobbered by signal context */
    *(unsigned long*)(regs.rsp - RED_ZONE_SIZE - 8) = regs.rip;

    /* Ready to resume execution, re-enable preemption. */
    shim_tcb_t* tcb = shim_get_tcb();
    __enable_preempt(tcb);

    unsigned long fs_base = context->fs_base;
    memset(context, 0, sizeof(struct shim_context));
    context->fs_base = fs_base;

    __asm__ volatile("movq %0, %%rsp\r\n"
                     "addq $2 * 8, %%rsp\r\n"    /* skip orig_rax and rsp */
                     "popq %%r15\r\n"
                     "popq %%r14\r\n"
                     "popq %%r13\r\n"
                     "popq %%r12\r\n"
                     "popq %%r11\r\n"
                     "popq %%r10\r\n"
                     "popq %%r9\r\n"
                     "popq %%r8\r\n"
                     "popq %%rcx\r\n"
                     "popq %%rdx\r\n"
                     "popq %%rsi\r\n"
                     "popq %%rdi\r\n"
                     "popq %%rbx\r\n"
                     "popq %%rbp\r\n"
                     "popfq\r\n"
                     "movq "XSTRINGIFY(SHIM_REGS_RSP)" - "XSTRINGIFY(SHIM_REGS_RIP)"(%%rsp), %%rsp\r\n"
                     "movq $0, %%rax\r\n"
                     "jmp *-"XSTRINGIFY(RED_ZONE_SIZE)"-8(%%rsp)\r\n"
                     :: "g"(&regs) : "memory");
}

/*
 * See syscall_wrapper @ syscalldb.S and illegal_upcall() @ shim_signal.c
 * for details.
 * child thread can _not_ use parent stack. So return right after syscall
 * instruction as if syscall_wrapper is executed.
 */
void fixup_child_context(struct shim_regs* regs) {
    if (regs->rip == (unsigned long)&syscall_wrapper_after_syscalldb) {
        /*
         * we don't need to emulate stack pointer change because %rsp is
         * initialized to new child user stack passed to clone() system call.
         * See the caller of fixup_child_context().
         */
        /* regs->rsp += RED_ZONE_SIZE; */
        regs->rflags = regs->r11;
        regs->rip = regs->rcx;
    }
}
