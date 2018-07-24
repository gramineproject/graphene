/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include "pal_linux.h"
#include "pal_security.h"
#include "pal_internal.h"
#include <api.h>

#include "ecall_types.h"
#include "rpcqueue.h"

#define SGX_CAST(type, item) ((type) (item))

void pal_linux_main (const char ** arguments, const char ** environments,
                     struct pal_sec * sec_info);

void pal_start_thread (void);

extern void * enclave_base, * enclave_top;

/* returns 0 if rpc_queue is valid, otherwise 1 */
static int set_rpc_queue(void* untrusted_rpc_queue) {
    rpc_queue = (rpc_queue_t*) untrusted_rpc_queue;
    if (!rpc_queue)
        return 0;

    if (sgx_is_within_enclave(rpc_queue, sizeof(*rpc_queue)))
        return 1;

    if (rpc_queue->rpc_threads_num > MAX_RPC_THREADS)
        return 1;

    /* re-initialize rest fields for safety */
    atomic_set(&rpc_queue->lock, 0);
    rpc_queue->front = 0;
    rpc_queue->rear  = 0;
    for (size_t i = 0; i < RPC_QUEUE_SIZE; i++)
        rpc_queue->q[i] = NULL;

    return 0;
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

    switch(ecall_index) {
        case ECALL_ENCLAVE_START: {
            ms_ecall_enclave_start_t * ms =
                    (ms_ecall_enclave_start_t *) ecall_args;

            if (!ms) return -PAL_ERROR_INVAL;

            if (set_rpc_queue(ms->rpc_queue))
                return -PAL_ERROR_DENIED;

            pal_linux_main(ms->ms_arguments, ms->ms_environments,
                           ms->ms_sec_info);
            break;
        }

        case ECALL_THREAD_START:
            pal_start_thread();
            break;
    }

    ocall_exit(0);
    return 0;
}
