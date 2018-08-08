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

struct thread_map {
    unsigned int         tid;
    unsigned int         thread_index;
    unsigned int         status;
    sgx_arch_tcs_t *     tcs;
    unsigned long        tcs_addr;
    unsigned long        ssa_addr;
    unsigned long        tls_addr;
    unsigned long 	 aux_stack_addr; /* only applicable to EDMM */
    unsigned long        enclave_entry;
};

/* pal_expand_stack grows the stack dynamically under EDMM mode, 
 * the growing strategy is (1) commit EPC pages to the space between
 * fault address and the current stack top; (2) commit one more EPC
 * page below the fault address for future stack grow

 * fault_addr: the address where causing #PF by push instructions
 */
void pal_expand_stack(unsigned long fault_addr)
{
    unsigned long stack_commit_top = GET_ENCLAVE_TLS(stack_commit_top);
    unsigned long accept_flags = SGX_SECINFO_FLAGS_R | SGX_SECINFO_FLAGS_W |
                        SGX_SECINFO_FLAGS_REG | SGX_SECINFO_FLAGS_PENDING;   
    unsigned long stack_init_addr = GET_ENCLAVE_TLS(initial_stack_offset);
    unsigned long end_addr = fault_addr - PRESET_PAGESIZE;

    SGX_DBG(DBG_M, "fault_addr, stack_commit_top, stack_init_addr: %p, %p, %p\n", 
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

/* This function setup the pages necessary for runing a thread including: 
 * (1) SSAs (2) TLS (3)TCS (4) Stack
 * ecall_args: pointer to the thread-dependent information for setup the new thread
 */
void pal_thread_setup(void * ecall_args){
    struct thread_map * thread_info = (struct thread_map *)ecall_args;
    unsigned long regular_flags = SGX_SECINFO_FLAGS_R | SGX_SECINFO_FLAGS_W |
                        SGX_SECINFO_FLAGS_REG | SGX_SECINFO_FLAGS_PENDING;
    SGX_DBG(DBG_M, "the created thread using tcs at  %p, tls at %p, ssa at %p\n", 
			thread_info->tcs_addr, thread_info->tls_addr, thread_info->ssa_addr);
    sgx_accept_pages(regular_flags, thread_info->tcs_addr, thread_info->tcs_addr + PRESET_PAGESIZE, 0);
    sgx_accept_pages(regular_flags, thread_info->tls_addr, thread_info->tls_addr + PRESET_PAGESIZE, 0);
    sgx_accept_pages(regular_flags, thread_info->ssa_addr, thread_info->ssa_addr + 2 * PRESET_PAGESIZE, 0);

    // Setup TLS
    struct enclave_tls* tls = (struct enclave_tls *) thread_info->tls_addr;
    tls->enclave_size = GET_ENCLAVE_TLS(enclave_size);
    tls->tcs_offset = thread_info->tcs_addr;

    unsigned long stack_gap = thread_info->thread_index * (ENCLAVE_STACK_SIZE + PRESET_PAGESIZE); // There is a gap between stacks
    tls->initial_stack_offset = GET_ENCLAVE_TLS(initial_stack_offset) - stack_gap;

    tls->ssa = (void *)thread_info->ssa_addr;
    tls->gpr = tls->ssa + PRESET_PAGESIZE - sizeof(sgx_arch_gpr_t);
    tls->aux_stack_offset = thread_info->aux_stack_addr;
    tls->stack_commit_top = tls->initial_stack_offset;
    tls->ocall_pending = 0;

    // Setup TCS
    thread_info->tcs = (sgx_arch_tcs_t *) thread_info->tcs_addr;
    memset((void*)thread_info->tcs_addr, 0, PRESET_PAGESIZE);
    thread_info->tcs->ossa = thread_info->ssa_addr;
    thread_info->tcs->nssa = 2;
    thread_info->tcs->oentry = thread_info->enclave_entry;
    thread_info->tcs->ofsbasgx = 0;
    thread_info->tcs->ogsbasgx = thread_info->tls_addr;
    thread_info->tcs->fslimit = 0xfff;
    thread_info->tcs->gslimit = 0xfff;
    
    // PRE-ALLOCATE two pages for STACK
    unsigned long accept_flags = SGX_SECINFO_FLAGS_R | SGX_SECINFO_FLAGS_W |
                        SGX_SECINFO_FLAGS_REG | SGX_SECINFO_FLAGS_PENDING;

    sgx_accept_pages(accept_flags, tls->initial_stack_offset - 2 * PRESET_PAGESIZE, tls->initial_stack_offset, 0);
}

/* pal_thread_create finalizes the creataion of thread by changing
 * the type of tcs page from regular to TCS 
 * ecall_args: the tcs page address to be TCS type
 */
void pal_thread_create(void * ecall_args){
    struct thread_map * thread_info = (struct thread_map *)ecall_args;
    unsigned long tcs_flags = SGX_SECINFO_FLAGS_TCS | SGX_SECINFO_FLAGS_MODIFIED;

    int rs = sgx_accept_pages(tcs_flags, thread_info->tcs_addr, thread_info->tcs_addr + PRESET_PAGESIZE, 0);
    if (rs != 0) SGX_DBG(DBG_E, "EACCEPT TCS Change failed: %d\n", rs);
}

/* handle_ecall is the main entry of all ecall functions */
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
	    pal_expand_stack((unsigned long)ecall_args);
	    break;
       case ECALL_THREAD_SETUP:
	    pal_thread_setup(ecall_args);
	    break;
       case ECALL_THREAD_CREATE:
	    pal_thread_create(ecall_args);
	    break;
       default:
	    SGX_DBG(DBG_E, "Ecall error, invalid ecall index!\n");
	    ocall_exit(); 
    }
    
    return 0;
}
