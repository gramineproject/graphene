#include <generated-offsets-build.h>

#include <stddef.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <shim_internal.h>
#include <shim_tcb.h>

void dummy(void)
{
    OFFSET_T(SHIM_TCB_OFFSET, PAL_TCB, libos_tcb);
    OFFSET_T(TCB_REGS, shim_tcb_t, context.regs);
    OFFSET_T(SHIM_TCB_FLAGS, shim_tcb_t, flags);
    OFFSET_T(SHIM_TCB_TMP_RIP, shim_tcb_t, tmp_rip);
    OFFSET_T(SHIM_TCB_SYSCALL_STACK, shim_tcb_t, syscall_stack);
    OFFSET(SHIM_REGS_R11, shim_regs, r11);
    OFFSET(SHIM_REGS_RIP, shim_regs, rip);
    OFFSET(SHIM_REGS_RSP, shim_regs, rsp);
    DEFINE(SHIM_REGS_SIZE, sizeof(struct shim_regs));

    /* definitions */
    DEFINE(RED_ZONE_SIZE, RED_ZONE_SIZE);
    DEFINE(SHIM_FLAG_MAY_DELIVER_SIGNAL, SHIM_FLAG_MAY_DELIVER_SIGNAL);
    DEFINE(__NR_gettid, __NR_gettid);
}

