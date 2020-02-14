#ifndef __SGX_TLS_H__
#define __SGX_TLS_H__

#include <pal.h>

struct untrusted_area {
    void* mem;
    uint64_t size;
    uint64_t in_use;
    bool valid;
};

/*
 * Beside the classic thread local storage (like ustack, thread, etc.) the TLS
 * area is also used to pass parameters needed during enclave or thread
 * initialization. Some of them are thread specific (like tcs_offset) and some
 * of them are identical for all threads (like enclave_size).
 */
struct enclave_tls {
    PAL_TCB common;

    /* private to Linux-SGX PAL */
    uint64_t enclave_size;
    uint64_t tcs_offset;
    uint64_t initial_stack_offset;
    uint64_t tmp_rip;
    uint64_t sig_stack_low;
    uint64_t sig_stack_high;
    void*    ecall_return_addr;
    void*    ssa;
    sgx_pal_gpr_t* gpr;
    void*    exit_target;
    void*    fsbase;
    void*    pre_ocall_stack;
    void*    ustack_top;
    void*    ustack;
    struct pal_handle_thread* thread;
    uint64_t ocall_exit_called;
    uint64_t thread_started;
    uint64_t ready_for_exceptions;
    uint64_t manifest_size;
    void*    heap_min;
    void*    heap_max;
    void*    exec_addr;
    uint64_t exec_size;
    int*     clear_child_tid;
    struct untrusted_area untrusted_area_cache;
};

#ifndef DEBUG
extern uint64_t dummy_debug_variable;
#endif

# ifdef IN_ENCLAVE

static inline struct enclave_tls* get_tcb_trts(void) {
    return (struct enclave_tls*)pal_get_tcb();
}

#  define GET_ENCLAVE_TLS(member)                                   \
    ({                                                              \
        struct enclave_tls * tmp;                                   \
        uint64_t val;                                               \
        static_assert(sizeof(tmp->member) == 8,                     \
                      "sgx_tls member should have 8-byte type");    \
        __asm__ ("movq %%gs:%c1, %q0": "=r" (val)                   \
             : "i" (offsetof(struct enclave_tls, member)));         \
        (__typeof(tmp->member)) val;                                \
    })
#  define SET_ENCLAVE_TLS(member, value)                            \
    do {                                                            \
        struct enclave_tls * tmp;                                   \
        static_assert(sizeof(tmp->member) == 8,                     \
                      "sgx_tls member should have 8-byte type");    \
        static_assert(sizeof(value) == 8,                           \
                      "only 8-byte type can be set to sgx_tls");    \
        __asm__ ("movq %q0, %%gs:%c1":: "r" (value),                \
             "i" (offsetof(struct enclave_tls, member)));           \
    } while (0)
# else
/* private to untrusted Linux PAL, unique to each untrusted thread */
typedef struct pal_tcb_urts {
    struct pal_tcb_urts* self;
    sgx_arch_tcs_t*     tcs;       /* TCS page of SGX corresponding to thread, for EENTER */
    void*               stack;     /* bottom of stack, for later freeing when thread exits */
    void*               alt_stack; /* bottom of alt stack, for child thread to init alt stack */
} PAL_TCB_URTS;

extern void pal_tcb_urts_init(PAL_TCB_URTS* tcb, void* stack, void* alt_stack);

static inline PAL_TCB_URTS* get_tcb_urts(void) {
    PAL_TCB_URTS* tcb;
    __asm__ ("movq %%gs:%c1, %q0\n"
             : "=r" (tcb)
             : "i" (offsetof(PAL_TCB_URTS, self)));
    return tcb;
}
# endif

#endif /* __SGX_TLS_H__ */
