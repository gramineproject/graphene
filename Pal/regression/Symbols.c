/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include "pal.h"
#include "pal_debug.h"

#define SYMBOL_ADDR(sym)                                        \
    ({  void * _sym;                                            \
        __asm__ volatile ("movq " #sym "@GOTPCREL(%%rip), %0"   \
                          : "=r"(_sym));                        \
        _sym; })

#define PRINT_SYMBOL(sym) pal_printf(#sym " = %p\n", SYMBOL_ADDR(sym))

int main (int argc, char ** argv, char ** envp)
{
    PRINT_SYMBOL(DkVirtualMemoryAlloc);
    PRINT_SYMBOL(DkVirtualMemoryFree);
    PRINT_SYMBOL(DkVirtualMemoryProtect);

    PRINT_SYMBOL(DkProcessCreate);
    PRINT_SYMBOL(DkProcessExit);
    PRINT_SYMBOL(DkProcessSandboxCreate);

    PRINT_SYMBOL(DkStreamOpen);
    PRINT_SYMBOL(DkStreamWaitForClient);
    PRINT_SYMBOL(DkStreamRead);
    PRINT_SYMBOL(DkStreamWrite);
    PRINT_SYMBOL(DkStreamDelete);
    PRINT_SYMBOL(DkStreamMap);
    PRINT_SYMBOL(DkStreamUnmap);
    PRINT_SYMBOL(DkStreamSetLength);
    PRINT_SYMBOL(DkStreamFlush);
    PRINT_SYMBOL(DkSendHandle);
    PRINT_SYMBOL(DkReceiveHandle);
    PRINT_SYMBOL(DkStreamAttributesQuery);
    PRINT_SYMBOL(DkStreamAttributesQueryByHandle);
    PRINT_SYMBOL(DkStreamAttributesSetByHandle);
    PRINT_SYMBOL(DkStreamGetName);
    PRINT_SYMBOL(DkStreamChangeName);

    PRINT_SYMBOL(DkThreadCreate);
    PRINT_SYMBOL(DkThreadDelayExecution);
    PRINT_SYMBOL(DkThreadYieldExecution);
    PRINT_SYMBOL(DkThreadExit);
    PRINT_SYMBOL(DkThreadResume);

    PRINT_SYMBOL(DkSetExceptionHandler);
    PRINT_SYMBOL(DkExceptionReturn);

    PRINT_SYMBOL(DkMutexCreate);
    PRINT_SYMBOL(DkMutexRelease);
    PRINT_SYMBOL(DkNotificationEventCreate);
    PRINT_SYMBOL(DkSynchronizationEventCreate);
    PRINT_SYMBOL(DkEventSet);
    PRINT_SYMBOL(DkEventClear);

    PRINT_SYMBOL(DkObjectsWaitAny);
    PRINT_SYMBOL(DkObjectClose);

    PRINT_SYMBOL(DkSystemTimeQuery);
    PRINT_SYMBOL(DkRandomBitsRead);
    PRINT_SYMBOL(DkInstructionCacheFlush);
    PRINT_SYMBOL(DkSegmentRegister);
    PRINT_SYMBOL(DkMemoryAvailableQuota);

    PRINT_SYMBOL(DkCreatePhysicalMemoryChannel);
    PRINT_SYMBOL(DkPhysicalMemoryCommit);
    PRINT_SYMBOL(DkPhysicalMemoryMap);

    return 0;
}
