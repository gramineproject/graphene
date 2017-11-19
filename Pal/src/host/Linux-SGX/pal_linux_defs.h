/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#ifndef PAL_LINUX_DEFS_H
#define PAL_LINUX_DEFS_H

#define ENCLAVE_HIGH_ADDRESS    (0x800000000)
#define SSAFRAMENUM         (2)
#define MEMORY_GAP          (PRESET_PAGESIZE)
#define ENCLAVE_STACK_SIZE  (PRESET_PAGESIZE * 16)
#define DEAFULT_HEAP_MIN    (0x10000)
#define TRACE_ECALL         (1)
#define TRACE_OCALL         (1)

#define DEBUG_ECALL         (0)
#define DEBUG_OCALL         (0)

#define SGX_HAS_FSGSBASE    (1)

#define TRUSTED_STUB_SIZE   (PRESET_PAGESIZE * 4)

#define CACHE_FILE_STUBS    (1)

//#define USE_AES_NI          (1)

#define PRINT_ENCLAVE_STAT  (0)

#endif /* PAL_LINUX_DEFS_H */
