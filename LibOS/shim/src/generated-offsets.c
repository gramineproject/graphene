#include <generated-offsets-build.h>

#include <stddef.h>

#include <shim_internal.h>
#include <shim_tls.h>

void dummy(void)
{
    OFFSET_T(SHIM_TCB_OFFSET, __libc_tcb_t, shim_tcb);
    OFFSET_T(TCB_REGS, shim_tcb_t, context.regs);
    OFFSET(SHIM_REGS_SP, shim_regs, sp);
    OFFSET(SHIM_REGS_R15, shim_regs, r15);
    OFFSET(SHIM_REGS_RET_IP, shim_regs, ret_ip);
    DEFINE(SHIM_REGS_SIZE, sizeof(struct shim_regs));

    /* definitions */
    DEFINE(RED_ZONE_SIZE, RED_ZONE_SIZE);
}

