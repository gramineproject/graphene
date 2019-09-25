#include <generated-offsets-build.h>

#include <stddef.h>

#include <shim_internal.h>
#include <shim_tls.h>

void dummy(void)
{
#ifdef SHIM_TCB_USE_GS
    OFFSET_T(SHIM_TCB_OFFSET, PAL_TCB, libos_tcb);
#else
    OFFSET_T(SHIM_TCB_OFFSET, __libc_tcb_t, shim_tcb);
#endif
    OFFSET_T(TCB_REGS, shim_tcb_t, context.regs);
    OFFSET(SHIM_REGS_RSP, shim_regs, rsp);
    OFFSET(SHIM_REGS_R15, shim_regs, r15);
    OFFSET(SHIM_REGS_RIP, shim_regs, rip);
    DEFINE(SHIM_REGS_SIZE, sizeof(struct shim_regs));

    /* definitions */
    DEFINE(RED_ZONE_SIZE, RED_ZONE_SIZE);
}

