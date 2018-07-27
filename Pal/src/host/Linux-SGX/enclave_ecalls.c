/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include "pal_linux.h"
#include "pal_security.h"
#include "pal_internal.h"
#include <api.h>

#include "ecall_types.h"

#define SGX_CAST(type, item) ((type) (item))

void pal_linux_main (const char ** arguments, const char ** environments,
                     struct pal_sec * sec_info);

void pal_start_thread (void);

extern void * enclave_base, * enclave_top;

void pal_expand_stack(unsigned long fault_addr)
{
    unsigned long stack_commit_top = GET_ENCLAVE_TLS(stack_commit_top);
    unsigned long accept_flags = SGX_SECINFO_FLAGS_R | SGX_SECINFO_FLAGS_W |
                        SGX_SECINFO_FLAGS_REG | SGX_SECINFO_FLAGS_PENDING;   
    unsigned long stack_init_addr = GET_ENCLAVE_TLS(initial_stack_offset);
    unsigned long end_addr = fault_addr - PRESET_PAGESIZE;

    SGX_DBG(DBG_E, "fault_addr, stack_commit_top, stack_init_addr: %p, %p, %p\n", 
		fault_addr, stack_commit_top, stack_init_addr);
    if (fault_addr < (stack_init_addr - ENCLAVE_STACK_SIZE * PRESET_PAGESIZE)) {
        SGX_DBG(DBG_E, "stack overrun, stop!\n");
        return ;
    }
    /* Bridge the gap between fault addr and top if any */
    sgx_accept_pages(accept_flags, fault_addr, stack_commit_top, 0);
    
    stack_commit_top = fault_addr;
    /* Overgrow one more page */
    if (end_addr >= stack_init_addr - ENCLAVE_STACK_SIZE * PRESET_PAGESIZE) {
        sgx_accept_pages(accept_flags, end_addr, fault_addr, 0);
        stack_commit_top = fault_addr;
    }

}

int handle_ecall (long ecall_index, void * ecall_args, void * exit_target,
                  void * untrusted_stack, void * enclave_base_addr)
{
    if (ecall_index < 0 || ecall_index >= ECALL_NR)
        return -PAL_ERROR_INVAL;

    if (!enclave_base) {
        enclave_base = enclave_base_addr;
        enclave_top = enclave_base_addr + GET_ENCLAVE_TLS(enclave_size);
    }

    if (sgx_is_within_enclave(exit_target, 0))
        return -PAL_ERROR_DENIED;

    if (sgx_is_within_enclave(untrusted_stack, 0))
        return -PAL_ERROR_DENIED;

    SET_ENCLAVE_TLS(exit_target, exit_target);
    SET_ENCLAVE_TLS(ustack_top,  untrusted_stack);
    SET_ENCLAVE_TLS(ustack,      untrusted_stack);
    SET_ENCLAVE_TLS(ocall_pending, 0);
    void * utr_stack = GET_ENCLAVE_TLS(ustack);
    SGX_DBG(DBG_E, "utrusted stack: %p\n", utr_stack);
    switch(ecall_index) {
        case ECALL_ENCLAVE_START: {
            ms_ecall_enclave_start_t * ms =
                    (ms_ecall_enclave_start_t *) ecall_args;

            if (!ms) return -PAL_ERROR_INVAL;

            pal_linux_main(ms->ms_arguments, ms->ms_environments,
                           ms->ms_sec_info);
	    ocall_exit();
            break;
        }

        case ECALL_THREAD_START:
            pal_start_thread();
	    ocall_exit();
            break;
        case ECALL_STACK_EXPAND:
            pal_expand_stack(ecall_args);
	    break;
    }
    utr_stack = GET_ENCLAVE_TLS(ustack);
    SGX_DBG(DBG_E, "untrusted stack after: %p\n", utr_stack);
    SGX_DBG(DBG_E, "exit_target: %p\n", GET_ENCLAVE_TLS(exit_target));
    return 0;
}
