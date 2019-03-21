#include <asm-offsets-build.h>

#include <stddef.h>

#include <shim_internal.h>
#include <shim_tls.h>

void dummy(void)
{
    OFFSET_T(SHIM_TCB_OFFSET, __libc_tcb_t, shim_tcb);
    OFFSET_T(TCB_SYSCALL_NR, shim_tcb_t, context.syscall_nr);
    OFFSET_T(TCB_SP, shim_tcb_t, context.sp);
    OFFSET_T(TCB_RET_IP, shim_tcb_t, context.ret_ip);
    OFFSET_T(TCB_REGS, shim_tcb_t, context.regs);
}

