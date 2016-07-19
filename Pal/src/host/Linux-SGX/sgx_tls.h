/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#ifndef __SGX_TLS_H__
#define __SGX_TLS_H__

#ifndef __ASSEMBLER__

struct enclave_tls {
    void *          self;
    void *          initial_stack;
    void *          fsbase;
    unsigned long   ssaframesize;
    void *          ssa;
    void *          gpr;
    void *          exit_target;
    unsigned long * debug_register;
    void *          urts_initial_stack;
    void *          urts_stack;
    void *          aep;
    void *          last_stack;
    unsigned long   last_ocall_result;
    void *          thread;
    unsigned long   external_event;
};

# ifdef IN_ENCLAVE
#  define ENCLAVE_TLS_SELF()                                    \
    ({ struct enclave_tls *__self;                              \
        asm ("movq %%gs:%c1, %q0" : "=r" (__self)               \
           : "i" (offsetof(struct enclave_tls, self)));         \
      __self; })

#  define ENCLAVE_TLS(member)                                   \
    (((struct enclave_tls *) ENCLAVE_TLS_SELF())->member)

#  define DEBUG_REG (*ENCLAVE_TLS(debug_register))
# endif

#else /* !__ASSEMBLER__ */

# ifdef IN_ENCLAVE
#  define DEBUG_REG %gs:SGX_DEBUG_REGISTER
# endif

#endif

/* update these constant according to struct enclave_tls */
#define SGX_INITIAL_STACK       0x08
#define SGX_FSBASE              0x10
#define SGX_SSAFRAMESIZE        0x18
#define SGX_SSA                 0x20
#define SGX_GPR                 0x28
#define SGX_EXIT_TARGET         0x30
#define SGX_DEBUG_REGISTER      0x38
#define SGX_URTS_INITIAL_STACK  0x40
#define SGX_URTS_STACK          0x48
#define SGX_AEP                 0x50
#define SGX_LAST_STACK          0x58
#define SGX_LAST_OCALL_RESULT   0x60
#define SGX_THREAD              0x78
#define SGX_EXTERNAL_EVENT      0x70


#endif /* __SGX_TLS_H__ */
