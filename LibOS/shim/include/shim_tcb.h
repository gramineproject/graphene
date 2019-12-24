#ifndef _SHIM_TCB_H_
#define _SHIM_TCB_H_

#include <atomic.h>

#define SHIM_TCB_CANARY 0xdeadbeef

struct shim_regs {
    unsigned long           orig_rax;
    unsigned long           rsp;
    unsigned long           r15;
    unsigned long           r14;
    unsigned long           r13;
    unsigned long           r12;
    unsigned long           r11;
    unsigned long           r10;
    unsigned long           r9;
    unsigned long           r8;
    unsigned long           rcx;
    unsigned long           rdx;
    unsigned long           rsi;
    unsigned long           rdi;
    unsigned long           rbx;
    unsigned long           rbp;
    unsigned long           rflags;
    unsigned long           rip;
};

struct shim_context {
    struct shim_regs *      regs;
    unsigned long           fs_base;
    struct shim_context *   next;
    uint64_t                enter_time;
    struct atomic_int       preempt;
};

struct debug_buf;

typedef struct shim_tcb shim_tcb_t;
struct shim_tcb {
    uint64_t                canary;
    shim_tcb_t *            self;
    struct shim_thread *    tp;
    struct shim_context     context;
    unsigned int            tid;
    int                     pal_errno;
    struct debug_buf *      debug_buf;

    /* This record is for testing the memory of user inputs.
     * If a segfault occurs with the range [start, end],
     * the code addr is set to cont_addr to alert the caller. */
    struct {
        void * start, * end;
        void * cont_addr;
        bool has_fault;
    } test_range;
};

void init_tcb (shim_tcb_t * tcb);

#define SHIM_TCB_GET(member)                                            \
    ({                                                                  \
        shim_tcb_t* tcb;                                                \
        static_assert(sizeof(tcb->member) == 8,                         \
                      "SHIM_TCB_GET can be used only for 8-bytes member"); \
        __typeof__(tcb->member) ret;                                    \
        __asm__ ("movq %%gs:%c1,%q0"                                    \
                 : "=r"(ret)                                            \
                 : "i" (offsetof(PAL_TCB, libos_tcb) +                  \
                        offsetof(shim_tcb_t, member)));                 \
        ret;                                                            \
    })

#define SHIM_TCB_SET(member, value)                                     \
    do {                                                                \
        shim_tcb_t* tcb;                                                \
        static_assert(sizeof(tcb->member) == 8,                         \
                      "SHIM_TCB_SET can be used only for 8-bytes member"); \
        __asm__ ("movq %q0, %%gs:%c1":: "r"(value),                     \
                 "i"(offsetof(PAL_TCB, libos_tcb) +                     \
                     offsetof(shim_tcb_t, member)));                    \
    } while (0)

/* Setup shim_tcb_t::self so that shim_get_tcb() work.
 * Call this function at the beginning of thread execution.
 */
static inline void shim_tcb_init(void) {
    PAL_TCB * tcb = pal_get_tcb();
    shim_tcb_t* shim_tcb = (shim_tcb_t*)tcb->libos_tcb;
    shim_tcb->self = shim_tcb;
}

static inline shim_tcb_t * shim_get_tcb(void)
{
    return SHIM_TCB_GET(self);
}

static inline bool shim_tcb_check_canary(void)
{
    return SHIM_TCB_GET(canary) == SHIM_TCB_CANARY;
}

#endif /* _SHIM_H_ */
