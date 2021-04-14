#ifndef _SHIM_TCB_H_
#define _SHIM_TCB_H_

#include "api.h"
#include "assert.h"
#include "atomic.h"
#include "pal.h"
#include "shim_entry.h"
#include "shim_entry_api.h"
#include "shim_tcb-arch.h"

#define SHIM_TCB_CANARY 0xdeadbeef

struct shim_context {
    PAL_CONTEXT* regs;
    long syscall_nr;
    unsigned long tls; /* Used only in clone. */
};

typedef struct shim_tcb shim_tcb_t;
struct shim_tcb {
    uint64_t            canary;
    shim_tcb_t*         self;

    /* Function pointers for patched code calling into Graphene. */
    void*               syscalldb;
    void*               register_library;

    struct shim_thread* tp;
    void*               libos_stack_bottom;
    struct shim_context context;
    /* Scratch space to temporarily store a register. On some architectures (e.g. x86_64 inside
     * an SGX enclave) we lack a way to restore all (or at least some) registers atomically. */
    void*               syscall_scratch_pc;
    void*               vma_cache;
    char                log_prefix[32];

    /* This record is for testing the memory of user inputs.
     * If a segfault occurs with the range [start, end],
     * the code addr is set to cont_addr to alert the caller. */
    struct {
        void* start;
        void* end;
        void* cont_addr;
        bool has_fault;
    } test_range;
};

static_assert(
    offsetof(PAL_TCB, libos_tcb) + offsetof(shim_tcb_t, syscalldb) == SHIM_SYSCALLDB_OFFSET,
    "SHIM_SYSCALLDB_OFFSET must match");

static_assert(
    offsetof(PAL_TCB, libos_tcb) + offsetof(shim_tcb_t, register_library) ==
        SHIM_REGISTER_LIBRARY_OFFSET,
    "SHIM_REGISTER_LIBRARY_OFFSET must match");

static inline void __shim_tcb_init(shim_tcb_t* shim_tcb) {
    shim_tcb->canary = SHIM_TCB_CANARY;
    shim_tcb->self = shim_tcb;
    shim_tcb->syscalldb = &syscalldb;
    shim_tcb->register_library = &register_library;
    shim_tcb->context.syscall_nr = -1;
    shim_tcb->vma_cache = NULL;
}

/* Call this function at the beginning of thread execution. */
static inline void shim_tcb_init(void) {
    PAL_TCB* tcb = pal_get_tcb();
    static_assert(sizeof(shim_tcb_t) <= sizeof(((PAL_TCB*)0)->libos_tcb),
                  "Not enough space for LibOS TCB inside Pal TCB");
    shim_tcb_t* shim_tcb = (shim_tcb_t*)tcb->libos_tcb;
    memset(shim_tcb, 0, sizeof(*shim_tcb));
    __shim_tcb_init(shim_tcb);
}

static inline shim_tcb_t* shim_get_tcb(void) {
    return SHIM_TCB_GET(self);
}

static inline bool shim_tcb_check_canary(void) {
    return SHIM_TCB_GET(canary) == SHIM_TCB_CANARY;
}

#endif /* _SHIM_H_ */
