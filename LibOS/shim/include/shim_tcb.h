#ifndef _SHIM_TCB_H_
#define _SHIM_TCB_H_

#include "api.h"
#include "assert.h"
#include "atomic.h"
#include "pal.h"
#include "shim_tcb-arch.h"

#define SHIM_TCB_CANARY 0xdeadbeef

struct shim_context {
    PAL_CONTEXT* regs;
    long syscall_nr;
    unsigned long tls_base; /* Used only in clone. */
};

struct debug_buf;

typedef struct shim_tcb shim_tcb_t;
struct shim_tcb {
    uint64_t            canary;
    shim_tcb_t*         self;
    struct shim_thread* tp;
    void*               libos_stack_bottom;
    struct shim_context context;
    void*               syscall_scratch_pc;
    int                 pal_errno;
    struct debug_buf*   debug_buf;
    void*               vma_cache;

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

static inline void __shim_tcb_init(shim_tcb_t* shim_tcb) {
    shim_tcb->canary    = SHIM_TCB_CANARY;
    shim_tcb->self      = shim_tcb;
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
