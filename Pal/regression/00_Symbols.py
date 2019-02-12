#!/usr/bin/env python2

import os, sys, mmap
from regression import Regression

loader = os.environ['PAL_LOADER']

regression = Regression(loader, "Symbols")

all_symbols = [
    'DkVirtualMemoryAlloc',
    'DkVirtualMemoryFree',
    'DkVirtualMemoryProtect',
    'DkProcessCreate',
    'DkProcessExit',
    'DkProcessSandboxCreate',
    'DkStreamOpen',
    'DkStreamWaitForClient',
    'DkStreamRead',
    'DkStreamWrite',
    'DkStreamDelete',
    'DkStreamMap',
    'DkStreamUnmap',
    'DkStreamSetLength',
    'DkStreamFlush',
    'DkSendHandle',
    'DkReceiveHandle',
    'DkStreamAttributesQuery',
    'DkStreamAttributesQuerybyHandle',
    'DkStreamAttributesSetbyHandle',
    'DkStreamGetName',
    'DkStreamChangeName',
    'DkThreadCreate',
    'DkThreadDelayExecution',
    'DkThreadYieldExecution',
    'DkThreadExit',
    'DkThreadResume',
    'DkSetExceptionHandler',
    'DkExceptionReturn',
    'DkMutexCreate',
    'DkMutexRelease',
    'DkNotificationEventCreate',
    'DkSynchronizationEventCreate',
    'DkEventSet',
    'DkEventClear',
    'DkObjectsWaitAny',
    'DkObjectClose',
    'DkSystemTimeQuery',
    'DkRandomBitsRead',
    'DkInstructionCacheFlush',
    'DkSegmentRegister',
    'DkMemoryAvailableQuota',
    'DkCreatePhysicalMemoryChannel',
    'DkPhysicalMemoryCommit',
    'DkPhysicalMemoryMap']

def check_symbols(res):
    for sym in all_symbols:
        found = False
        for line in res[0].log:
            if line and line.startswith(sym + ' = '):
                if line == sym + ' = 0x0':
                    return False
                found = True
                break
        if not found:
            return False
    return True

regression.add_check(name="Symbol Resolution", check=check_symbols);
rv = regression.run_checks()
if rv: sys.exit(rv)
