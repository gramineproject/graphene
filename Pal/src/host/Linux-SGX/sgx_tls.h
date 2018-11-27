#ifndef __SGX_TLS_H__
#define __SGX_TLS_H__

/*
 * Beside the classic thread local storage (like ustack, thread, etc.) the TLS
 * area is also used to pass parameters needed during enclave or thread
 * initialization. Some of them are thread specific (like tcs_offset) and some
 * of them are identical for all threads (like enclave_size).
 */
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
    uint64_t ocall_prepared;
    uint64_t ecall_called;
    uint64_t ready_for_exceptions;
    uint64_t manifest_size;
    void *   heap_min;
    void *   heap_max;
    void *   exec_addr;
    uint64_t exec_size;
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
