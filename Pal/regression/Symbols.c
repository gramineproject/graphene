/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include "pal.h"
#include "pal_debug.h"

#define symbol_addr(sym)                                        \
    ({  void * _sym;                                            \
        asm volatile ("movq " #sym "@GOTPCREL(%%rip), %0"       \
                      : "=r"(_sym));                            \
        _sym; })

#define print_symbol(sym) pal_printf(#sym " = %p\n", symbol_addr(sym))

int main (int argc, char ** argv, char ** envp)
{
    print_symbol(DkVirtualMemoryAlloc);
    print_symbol(DkVirtualMemoryFree);
    print_symbol(DkVirtualMemoryProtect);

    print_symbol(DkProcessCreate);
    print_symbol(DkProcessExit);
    print_symbol(DkProcessSandboxCreate);

    print_symbol(DkStreamOpen);
    print_symbol(DkStreamWaitForClient);
    print_symbol(DkStreamRead);
    print_symbol(DkStreamWrite);
    print_symbol(DkStreamDelete);
    print_symbol(DkStreamMap);
    print_symbol(DkStreamUnmap);
    print_symbol(DkStreamSetLength);
    print_symbol(DkStreamFlush);
    print_symbol(DkSendHandle);
    print_symbol(DkReceiveHandle);
    print_symbol(DkStreamAttributesQuery);
    print_symbol(DkStreamAttributesQuerybyHandle);
    print_symbol(DkStreamAttributesSetbyHandle);
    print_symbol(DkStreamGetName);
    print_symbol(DkStreamChangeName);

    print_symbol(DkThreadCreate);
    print_symbol(DkThreadDelayExecution);
    print_symbol(DkThreadYieldExecution);
    print_symbol(DkThreadExit);
    print_symbol(DkThreadResume);

    print_symbol(DkSetExceptionHandler);
    print_symbol(DkExceptionReturn);

    print_symbol(DkMutexCreate);
    print_symbol(DkMutexRelease);
    print_symbol(DkNotificationEventCreate);
    print_symbol(DkSynchronizationEventCreate);
    print_symbol(DkEventSet);
    print_symbol(DkEventClear);

    print_symbol(DkObjectsWaitAny);
    print_symbol(DkObjectClose);

    print_symbol(DkSystemTimeQuery);
    print_symbol(DkRandomBitsRead);
    print_symbol(DkInstructionCacheFlush);
    print_symbol(DkSegmentRegister);
    print_symbol(DkMemoryAvailableQuota);

    print_symbol(DkCreatePhysicalMemoryChannel);
    print_symbol(DkPhysicalMemoryCommit);
    print_symbol(DkPhysicalMemoryMap);

    return 0;
}
