/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#ifndef __SGX_TLS_H__
#define __SGX_TLS_H__

struct enclave_tls {
    uint64_t enclave_size;
    uint64_t tcs_offset;
    uint64_t initial_stack_offset;
    void *   aep;
    void *   ssa;
    sgx_arch_gpr_t * gpr;
    void *   exit_target;
    void *   fsbase;
    void *   stack;
    void *   ustack_top;
    void *   ustack;
    struct pal_handle_thread * thread;
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
# endif

#endif /* __SGX_TLS_H__ */
