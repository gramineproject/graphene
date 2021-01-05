#ifndef _SHIM_TCB_H_
#define _SHIM_TCB_H_

#include "api.h"
#include "assert.h"
#include "atomic.h"
#include "pal.h"
#include "shim_tcb-arch.h"

#define SHIM_TCB_CANARY 0xdeadbeef

struct shim_context {
    struct shim_regs* regs;
    struct shim_ext_context ext_ctx;
    uint64_t          tls_base;
    struct atomic_int preempt;
};

static inline unsigned long shim_context_get_sp(struct shim_context* sc) {
    return shim_regs_get_sp(sc->regs);
}

static inline void shim_context_set_sp(struct shim_context* sc, unsigned long sp) {
    shim_regs_set_sp(sc->regs, sp);
}

static inline unsigned long shim_context_get_syscallnr(struct shim_context* sc) {
    return shim_regs_get_syscallnr(sc->regs);
}

static inline void shim_context_set_syscallnr(struct shim_context* sc, unsigned long sc_num) {
    shim_regs_set_syscallnr(sc->regs, sc_num);
}

struct debug_buf;

typedef struct shim_tcb shim_tcb_t;
struct shim_tcb {
    uint64_t            canary;
    shim_tcb_t*         self;
    struct shim_thread* tp;
    struct shim_context context;
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
    shim_tcb->vma_cache = NULL;
}

/* Call this function at the beginning of thread execution. */
static inline void shim_tcb_init(void) {
    PAL_TCB* tcb = pal_get_tcb();
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

static inline void update_tls_base(unsigned long tls_base) {
    shim_tcb_t* shim_tcb = shim_get_tcb();
    shim_tcb->context.tls_base = tls_base;
    shim_arch_update_tls_base(tls_base);
    assert(shim_tcb_check_canary());
}

#endif /* _SHIM_H_ */
