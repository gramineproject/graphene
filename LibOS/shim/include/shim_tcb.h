#ifndef _SHIM_TCB_H_
#define _SHIM_TCB_H_

#include <assert.h>
#include <atomic.h>
#include <pal.h>

#include "shim_tcb-arch.h"

#define SHIM_TCB_CANARY 0xdeadbeef

struct shim_context {
    struct shim_regs *      regs;
    uint64_t                fs_base;
    struct shim_context *   next;
    struct atomic_int       preempt;
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

static inline void shim_context_set_syscallnr(struct shim_context* sc, unsigned long orig_reg) {
    shim_regs_set_syscallnr(sc->regs, orig_reg);
}

struct debug_buf;

typedef struct shim_tcb shim_tcb_t;
struct shim_tcb {
    uint64_t            canary;
    shim_tcb_t*         self;
    struct shim_thread* tp;
    struct shim_context context;
    unsigned int        tid;
    int                 pal_errno;
    struct debug_buf*   debug_buf;
    void*               vma_cache;

    /* This record is for testing the memory of user inputs.
     * If a segfault occurs with the range [start, end],
     * the code addr is set to cont_addr to alert the caller. */
    struct {
        void * start, * end;
        void * cont_addr;
        bool has_fault;
    } test_range;
};

#define SHIM_TCB_GET(member)                                            \
    ({                                                                  \
        shim_tcb_t* tcb;                                                \
        __typeof__(tcb->member) ret;                                    \
        static_assert(sizeof(ret) == 8 ||                               \
                      sizeof(ret) == 4 ||                               \
                      sizeof(ret) == 2 ||                               \
                      sizeof(ret) == 1,                                 \
                      "SHIM_TCB_GET can be used only for "              \
                      "8, 4, 2, or 1-byte(s) members");                 \
        switch (sizeof(ret)) {                                          \
        case 8:                                                         \
            __asm__("movq %%gs:%c1, %0\n"                               \
                    : "=r"(ret)                                         \
                    : "i" (offsetof(PAL_TCB, libos_tcb) +               \
                           offsetof(shim_tcb_t, member)));              \
            break;                                                      \
        case 4:                                                         \
            __asm__("movl %%gs:%c1, %0\n"                               \
                    : "=r"(ret)                                         \
                    : "i" (offsetof(PAL_TCB, libos_tcb) +               \
                           offsetof(shim_tcb_t, member)));              \
            break;                                                      \
        case 2:                                                         \
            __asm__("movw %%gs:%c1, %0\n"                               \
                    : "=r"(ret)                                         \
                    : "i" (offsetof(PAL_TCB, libos_tcb) +               \
                           offsetof(shim_tcb_t, member)));              \
            break;                                                      \
        case 1:                                                         \
            __asm__("movb %%gs:%c1, %0\n"                               \
                    : "=r"(ret)                                         \
                    : "i" (offsetof(PAL_TCB, libos_tcb) +               \
                           offsetof(shim_tcb_t, member)));              \
            break;                                                      \
        default:                                                        \
            __abort();                                                  \
        }                                                               \
        ret;                                                            \
    })

#define SHIM_TCB_SET(member, value)                                     \
    do {                                                                \
        shim_tcb_t* tcb;                                                \
        static_assert(sizeof(tcb->member) == 8 ||                       \
                      sizeof(tcb->member) == 4 ||                       \
                      sizeof(tcb->member) == 2 ||                       \
                      sizeof(tcb->member) == 1,                         \
                      "SHIM_TCB_SET can be used only for "              \
                      "8, 4, 2, or 1-byte(s) members");                 \
        switch (sizeof(tcb->member)) {                                  \
        case 8:                                                         \
            __asm__("movq %0, %%gs:%c1\n"                               \
                    :: "ir"(value),                                     \
                     "i"(offsetof(PAL_TCB, libos_tcb) +                 \
                         offsetof(shim_tcb_t, member)));                \
            break;                                                      \
        case 4:                                                         \
            __asm__("movl %0, %%gs:%c1\n"                               \
                    :: "ir"(value),                                     \
                     "i"(offsetof(PAL_TCB, libos_tcb) +                 \
                         offsetof(shim_tcb_t, member)));                \
            break;                                                      \
        case 2:                                                         \
            __asm__("movw %0, %%gs:%c1\n"                               \
                    :: "ir"(value),                                     \
                     "i"(offsetof(PAL_TCB, libos_tcb) +                 \
                         offsetof(shim_tcb_t, member)));                \
            break;                                                      \
        case 1:                                                         \
            __asm__("movb %0, %%gs:%c1\n"                               \
                    :: "ir"(value),                                     \
                     "i"(offsetof(PAL_TCB, libos_tcb) +                 \
                         offsetof(shim_tcb_t, member)));                \
            break;                                                      \
        default:                                                        \
            __abort();                                                  \
        }                                                               \
    } while (0)

static inline void __shim_tcb_init(shim_tcb_t* shim_tcb) {
    shim_tcb->canary = SHIM_TCB_CANARY;
    shim_tcb->self = shim_tcb;
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

#endif /* _SHIM_H_ */
