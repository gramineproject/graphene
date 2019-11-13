#include "pal_linux.h"
#include "pal_security.h"
#include "pal_internal.h"
#include <api.h>

#include "ecall_types.h"
#include "rpc_queue.h"

#define SGX_CAST(type, item) ((type)(item))

extern void * enclave_base, * enclave_top;

static struct atomic_int enclave_start_called = ATOMIC_INIT(0);

/* returns 0 if rpc_queue is valid/not requested, otherwise -1 */
static int verify_and_init_rpc_queue(rpc_queue_t* untrusted_rpc_queue) {
    g_rpc_queue = NULL;

    if (!untrusted_rpc_queue) {
        /* user app didn't request RPC queue (i.e., the app didn't request exitless syscalls) */
        return 0;
    }

    if (!sgx_is_completely_outside_enclave(untrusted_rpc_queue, sizeof(*untrusted_rpc_queue))) {
        /* malicious RPC queue object, return error */
        return -1;
    }

    g_rpc_queue = untrusted_rpc_queue;
    return 0;
}

/*
 * Called from enclave_entry.S to execute ecalls.
 *
 * During normal operation handle_ecall will not return. The exception is that
 * it will return if invalid parameters are passed. In this case
 * enclave_entry.S will go into an endless loop since a clean return to urts is
 * not easy in all cases.
 *
 * Parameters:
 *
 *  ecall_index:
 *      Number of requested ecall. Untrusted.
 *
 *  ecall_args:
 *      Pointer to arguments for requested ecall. Untrusted.
 *
 *  exit_target:
 *      Address to return to after EEXIT. Untrusted.
 *
 *  untrusted_stack:
 *      Address to urts stack. Restored before EEXIT and used for ocall
 *      arguments. Untrusted.
 *
 *  enclave_base_addr:
 *      Base address of enclave. Calculated dynamically in enclave_entry.S.
 *      Trusted.
 */
void handle_ecall (long ecall_index, void * ecall_args, void * exit_target,
                   void * untrusted_stack, void * enclave_base_addr)
{
    if (ecall_index < 0 || ecall_index >= ECALL_NR)
        return;

    if (!enclave_top) {
        enclave_base = enclave_base_addr;
        enclave_top = enclave_base_addr + GET_ENCLAVE_TLS(enclave_size);
    }

    SET_ENCLAVE_TLS(exit_target,     exit_target);
    SET_ENCLAVE_TLS(ustack_top,      untrusted_stack);
    SET_ENCLAVE_TLS(ustack,          untrusted_stack);
    SET_ENCLAVE_TLS(clear_child_tid, NULL);
    SET_ENCLAVE_TLS(untrusted_area_cache.in_use, 0UL);

    if (atomic_cmpxchg(&enclave_start_called, 0, 1) == 0) {
        // ENCLAVE_START not yet called, so only valid ecall is ENCLAVE_START.
        if (ecall_index != ECALL_ENCLAVE_START) {
            // To keep things simple, we treat an invalid ecall_index like an
            // unsuccessful call to ENCLAVE_START.
            return;
        }

        ms_ecall_enclave_start_t * ms =
                (ms_ecall_enclave_start_t *) ecall_args;

        if (!ms || !sgx_is_completely_outside_enclave(ms, sizeof(*ms))) {
            return;
        }

        if (verify_and_init_rpc_queue(ms->rpc_queue))
            return;

        /* xsave size must be initialized early */
        init_xsave_size(ms->ms_sec_info->enclave_attributes.xfrm);

        /* pal_linux_main is responsible to check the passed arguments */
        pal_linux_main(ms->ms_args, ms->ms_args_size,
                       ms->ms_env, ms->ms_env_size,
                       ms->ms_sec_info);
    } else {
        // ENCLAVE_START already called (maybe successfully, maybe not), so
        // only valid ecall is THREAD_START.
        if (ecall_index != ECALL_THREAD_START) {
            return;
        }

        // Only allow THREAD_START after successful enclave initialization.
        if (!(pal_enclave_state.enclave_flags & PAL_ENCLAVE_INITIALIZED)) {
            return;
        }

        pal_start_thread();
    }
    // pal_linux_main and pal_start_thread should never return.
}
