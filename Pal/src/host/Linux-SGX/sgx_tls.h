/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#ifndef __SGX_TLS_H__
#define __SGX_TLS_H__

struct enclave_tls {
    struct enclave_tls * self;
    uint64_t enclave_size;
    uint64_t tcs_offset;
    uint64_t initial_stack_offset;
    uint64_t sig_stack_low;
    uint64_t sig_stack_high;
#define SGX_TLS_FLAGS_ASYNC_EVENT_PENDING_BIT   (0)
#define SGX_TLS_FLAGS_EVENT_EXECUTING_BIT       (1)
#define SGX_TLS_FLAGS_ASYNC_ENVET_PENDING       (1UL << SGX_TLS_FLAGS_ASYNC_ENVET_PENDING_BIT)
#define SGX_TLS_FLAGS_EVENT_EXECUTING           (1UL << SGX_TLS_FLAGS_ENVET_EXECUTING_BIT)
    uint64_t flags;
#define PAL_EVENT_MASK(event)   (1UL << (event))
#define PAL_ASYNC_EVENT_MASK                    \
    (PAL_EVENT_MASK(PAL_EVENT_QUIT) |           \
     PAL_EVENT_MASK(PAL_EVENT_SUSPEND) |        \
     PAL_EVENT_MASK(PAL_EVENT_RESUME))
    uint64_t pending_async_event;
    struct atomic_int event_nest;
    void *   aep;
    void *   ssa;
    sgx_arch_gpr_t * gpr;
    void *   exit_target;
    void *   fsbase;
    void *   stack;
    void *   ustack_top;
    void *   ustack;
    struct pal_handle_thread * thread;
    uint64_t ocall_prepared;
    uint64_t ecall_called;
    uint64_t ready_for_exceptions;
};

#ifndef DEBUG
extern uint64_t dummy_debug_variable;
#endif

# ifdef IN_ENCLAVE
#  define GET_ENCLAVE_TLS(member)                                   \
    ({                                                              \
        struct enclave_tls * tmp;                                   \
        uint64_t val;                                               \
        __asm__ ("movq %%gs:%c1, %q0": "=r" (val)                   \
             : "i" (offsetof(struct enclave_tls, member)));         \
        (__typeof(tmp->member)) val;                                \
    })
#  define SET_ENCLAVE_TLS(member, value)                            \
    do {                                                            \
        __asm__ ("movq %q0, %%gs:%c1":: "r" (value),                \
             "i" (offsetof(struct enclave_tls, member)));           \
    } while (0)

static inline struct enclave_tls * get_enclave_tls(void)
{
        struct enclave_tls * __self;
        __asm__ ("movq %%gs:%c1, %q0": "=r" (__self)
             : "i" (offsetof(struct enclave_tls, self)));
        return __self;
}
# endif

#endif /* __SGX_TLS_H__ */
