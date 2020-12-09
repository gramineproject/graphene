#include <stddef.h>

#include "generated-offsets-build.h"
#include "shim_internal.h"
#include "shim_tcb.h"

__attribute__((__used__)) static void dummy(void) {
    OFFSET_T(SHIM_TCB_OFFSET, PAL_TCB, libos_tcb);
    OFFSET_T(SHIM_TCB_LIBOS_STACK, shim_tcb_t, libos_stack_bottom);
    OFFSET_T(SHIM_TCB_SCRATCH_PC, shim_tcb_t, syscall_scratch_pc);

    /* definitions */
    DEFINE(RED_ZONE_SIZE, RED_ZONE_SIZE);
}
