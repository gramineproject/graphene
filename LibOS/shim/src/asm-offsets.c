#include <stddef.h>

#include <shim_defs.h>
#include <shim_internal.h>
#include <shim_tls.h>

#define OFFSET_T(name, str_t, member)                       \
    asm volatile(".ascii \" #define " #name " %0 \"\n"::    \
                 "i"(offsetof(str_t, member)))

void dummy(void)
{
    /* shim_tcb_t */
#ifdef SHIM_TCB_USE_GS
    OFFSET_T(SHIM_TCB_OFFSET, PAL_TCB, libos_tcb);
#else
    OFFSET_T(SHIM_TCB_OFFSET, __libc_tcb_t, shim_tcb);
#endif
    OFFSET_T(TCB_SELF, shim_tcb_t, self);
    OFFSET_T(TCB_TP, shim_tcb_t, tp);
    OFFSET_T(TCB_SYSCALL_NR, shim_tcb_t, context.syscall_nr);
    OFFSET_T(TCB_SP, shim_tcb_t, context.sp);
    OFFSET_T(TCB_RET_IP, shim_tcb_t, context.ret_ip);
    OFFSET_T(TCB_REGS, shim_tcb_t, context.regs);
}

