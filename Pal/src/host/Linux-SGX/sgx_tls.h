/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#ifndef __SGX_TLS_H__
#define __SGX_TLS_H__

#ifndef __ASSEMBLER__

struct enclave_tls {
    uint64_t enclave_size;
    uint64_t tcs_offset;
    uint64_t initial_stack_offset;
    void *   aep;
    void *   ssa;
    void *   gpr;
    void *   exit_target;
    void *   fsbase;
    void *   stack;
    void *   ustack_top;
    void *   ustack;
    void *   thread;
};

#ifndef DEBUG
extern uint64_t dummy_debug_variable;
#endif

# ifdef IN_ENCLAVE
#  define GET_ENCLAVE_TLS(member)                                   \
    ({                                                              \
        struct enclave_tls * tmp;                                   \
        uint64_t val;                                               \
        asm ("movq %%gs:%c1, %q0": "=r" (val)                       \
             : "i" (offsetof(struct enclave_tls, member)));         \
        (typeof(tmp->member)) val;                                  \
    })
#  define SET_ENCLAVE_TLS(member, value)                            \
    do {                                                            \
        asm ("movq %q0, %%gs:%c1":: "r" (value),                    \
             "i" (offsetof(struct enclave_tls, member)));           \
    } while (0)
# endif

#else /* !__ASSEMBLER__ */

/* update these constant according to struct enclave_tls */
#define SGX_ENCLAVE_SIZE            0x00
#define SGX_TCS_OFFSET              0x08
#define SGX_INITIAL_STACK_OFFSET    0x10
#define SGX_AEP                     0x18
#define SGX_SSA                     0x20
#define SGX_GPR                     0x28
#define SGX_EXIT_TARGET             0x30
#define SGX_FSBASE                  0x38
#define SGX_STACK                   0x40
#define SGX_USTACK_TOP              0x48
#define SGX_USTACK                  0x50
#define SGX_THREAD                  0x58

#endif

#endif /* __SGX_TLS_H__ */
