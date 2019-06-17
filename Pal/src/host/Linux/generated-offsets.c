#include <stddef.h>

#include <generated-offsets-build.h>

#include "pal_linux.h"

void dummy(void)
{
    /* pal_linux.h */
#ifdef ENABLE_STACK_PROTECTOR
    OFFSET_T(STACK_PROTECTOR_CANARY, PAL_TCB, stack_protector_canary);
#endif
}

