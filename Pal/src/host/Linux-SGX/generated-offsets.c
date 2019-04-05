#include <stddef.h>

#include "sgx_arch.h"
#include "sgx_tls.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_security.h"

#include <generated-offsets-build.h>

void dummy(void)
{
    /* sgx_arch_gpr_t */
    OFFSET_T(SGX_GPR_RAX, sgx_arch_gpr_t, rax);
    OFFSET_T(SGX_GPR_RCX, sgx_arch_gpr_t, rcx);
    OFFSET_T(SGX_GPR_RDX, sgx_arch_gpr_t, rdx);
    OFFSET_T(SGX_GPR_RBX, sgx_arch_gpr_t, rbx);
    OFFSET_T(SGX_GPR_RSP, sgx_arch_gpr_t, rsp);
    OFFSET_T(SGX_GPR_RBP, sgx_arch_gpr_t, rbp);
    OFFSET_T(SGX_GPR_RSI, sgx_arch_gpr_t, rsi);
    OFFSET_T(SGX_GPR_RDI, sgx_arch_gpr_t, rdi);
    OFFSET_T(SGX_GPR_R8, sgx_arch_gpr_t, r8);
    OFFSET_T(SGX_GPR_R9, sgx_arch_gpr_t, r9);
    OFFSET_T(SGX_GPR_R10, sgx_arch_gpr_t, r10);
    OFFSET_T(SGX_GPR_R11, sgx_arch_gpr_t, r11);
    OFFSET_T(SGX_GPR_R12, sgx_arch_gpr_t, r12);
    OFFSET_T(SGX_GPR_R13, sgx_arch_gpr_t, r13);
    OFFSET_T(SGX_GPR_R14, sgx_arch_gpr_t, r14);
    OFFSET_T(SGX_GPR_R15, sgx_arch_gpr_t, r15);
    OFFSET_T(SGX_GPR_RFLAGS, sgx_arch_gpr_t, rflags);
    OFFSET_T(SGX_GPR_RIP, sgx_arch_gpr_t, rip);
    OFFSET_T(SGX_GPR_EXITINFO, sgx_arch_gpr_t, exitinfo);
    DEFINE(SGX_GPR_SIZE, sizeof(sgx_arch_gpr_t));

    /* sgx_context_t */
    OFFSET_T(SGX_CONTEXT_RAX, sgx_context_t, rax);
    OFFSET_T(SGX_CONTEXT_RCX, sgx_context_t, rcx);
    OFFSET_T(SGX_CONTEXT_RDX, sgx_context_t, rdx);
    OFFSET_T(SGX_CONTEXT_RBX, sgx_context_t, rbx);
    OFFSET_T(SGX_CONTEXT_RSP, sgx_context_t, rsp);
    OFFSET_T(SGX_CONTEXT_RBP, sgx_context_t, rbp);
    OFFSET_T(SGX_CONTEXT_RSI, sgx_context_t, rsi);
    OFFSET_T(SGX_CONTEXT_RDI, sgx_context_t, rdi);
    OFFSET_T(SGX_CONTEXT_R8, sgx_context_t, r8);
    OFFSET_T(SGX_CONTEXT_R9, sgx_context_t, r9);
    OFFSET_T(SGX_CONTEXT_R10, sgx_context_t, r10);
    OFFSET_T(SGX_CONTEXT_R11, sgx_context_t, r11);
    OFFSET_T(SGX_CONTEXT_R12, sgx_context_t, r12);
    OFFSET_T(SGX_CONTEXT_R13, sgx_context_t, r13);
    OFFSET_T(SGX_CONTEXT_R14, sgx_context_t, r14);
    OFFSET_T(SGX_CONTEXT_R15, sgx_context_t, r15);
    OFFSET_T(SGX_CONTEXT_RFLAGS, sgx_context_t, rflags);
    OFFSET_T(SGX_CONTEXT_RIP, sgx_context_t, rip);
    DEFINE(SGX_CONTEXT_SIZE, sizeof(sgx_context_t));

    /* struct enclave_tls */
    OFFSET(SGX_ENCLAVE_SIZE, enclave_tls, enclave_size);
    OFFSET(SGX_TCS_OFFSET, enclave_tls, tcs_offset);
    OFFSET(SGX_INITIAL_STACK_OFFSET, enclave_tls, initial_stack_offset);
    OFFSET(SGX_AEP, enclave_tls, aep);
    OFFSET(SGX_SSA, enclave_tls, ssa);
    OFFSET(SGX_GPR, enclave_tls, gpr);
    OFFSET(SGX_EXIT_TARGET, enclave_tls, exit_target);
    OFFSET(SGX_FSBASE, enclave_tls, fsbase);
    OFFSET(SGX_STACK, enclave_tls, stack);
    OFFSET(SGX_USTACK_TOP, enclave_tls, ustack_top);
    OFFSET(SGX_USTACK, enclave_tls, ustack);
    OFFSET(SGX_THREAD, enclave_tls, thread);
    OFFSET(SGX_OCALL_PREPARED, enclave_tls, ocall_prepared);
    OFFSET(SGX_ECALL_CALLED, enclave_tls, ecall_called);
    OFFSET(SGX_READY_FOR_EXCEPTIONS, enclave_tls, ready_for_exceptions);
    OFFSET(SGX_MANIFEST_SIZE, enclave_tls, manifest_size);
    OFFSET(SGX_HEAP_MIN, enclave_tls, heap_min);
    OFFSET(SGX_HEAP_MAX, enclave_tls, heap_max);
    OFFSET(SGX_EXEC_ADDR, enclave_tls, exec_addr);
    OFFSET(SGX_EXEC_SIZE, enclave_tls, exec_size);

    /* sgx_arch_tcs_t */
    OFFSET_T(TCS_OSSA, sgx_arch_tcs_t, ossa);
    OFFSET_T(TCS_NSSA, sgx_arch_tcs_t, nssa);
    OFFSET_T(TCS_OENTRY, sgx_arch_tcs_t, oentry);
    OFFSET_T(TCS_OGSBASGX, sgx_arch_tcs_t, ogsbasgx);
    OFFSET_T(TCS_FSLIMIT, sgx_arch_tcs_t, fslimit);
    OFFSET_T(TCS_GSLIMIT, sgx_arch_tcs_t, gslimit);
    DEFINE(TCS_SIZE, sizeof(sgx_arch_tcs_t));

    /* sgx_arch_attributes_t */
    OFFSET_T(SGX_ARCH_ATTRIBUTES_XFRM, sgx_arch_attributes_t, xfrm);

    /* struct pal_sec */
    OFFSET(PAL_SEC_ENCLAVE_ATTRIBUTES, pal_sec, enclave_attributes);

    /* pal_linux_def.h */
    DEFINE(ENCLAVE_HIGH_ADDRESS, ENCLAVE_HIGH_ADDRESS);
    DEFINE(SSAFRAMENUM, SSAFRAMENUM);
    DEFINE(MEMORY_GAP, MEMORY_GAP);
    DEFINE(ENCLAVE_STACK_SIZE, ENCLAVE_STACK_SIZE);
    DEFINE(DEFAULT_HEAP_MIN, DEAFULT_HEAP_MIN);

    /* pal_linux.h */
    DEFINE(PAGESIZE, PRESET_PAGESIZE);
}

