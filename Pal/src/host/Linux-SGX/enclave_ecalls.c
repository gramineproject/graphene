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

static struct atomic_int enclave_start_called = ATOMIC_INIT(0);

void handle_ecall (long ecall_index, void * ecall_args, void * exit_target,
                   void * untrusted_stack, void * enclave_base_addr)
{
    if (ecall_index < 0 || ecall_index >= ECALL_NR)
        return;

    if (!enclave_top) {
        enclave_base = enclave_base_addr;
        enclave_top = enclave_base_addr + GET_ENCLAVE_TLS(enclave_size);
    }

    SET_ENCLAVE_TLS(exit_target, exit_target);
    SET_ENCLAVE_TLS(ustack_top,  untrusted_stack);
    SET_ENCLAVE_TLS(ustack,      untrusted_stack);

    if (atomic_cmpxchg(&enclave_start_called, 0, 1) == 0) {
        // ENCALVE_START not yet called, so only valid ecall is ENCLAVE_START.
        if (ecall_index != ECALL_ENCLAVE_START) {
            // To keep things simple, we treat an invalid ecall_index like an
            // unsuccessful call to ENCLAVE_START.
            return;
        }

        ms_ecall_enclave_start_t * ms =
                (ms_ecall_enclave_start_t *) ecall_args;

        if (!ms) return;

        pal_linux_main(ms->ms_arguments, ms->ms_environments,
                       ms->ms_sec_info);
    } else {
        // ENCALVE_START already called (maybe successfully, maybe not), so
        // only valid ecall is THREAD_START.
        if (ecall_index != ECALL_THREAD_START) {
            return;
        }

        // Only allow THREAD_START after successfully enclave initialization.
        if (!(pal_enclave_state.enclave_flags & PAL_ENCLAVE_INITIALIZED)) {
            return;
        }

        pal_start_thread();
    }
    // pal_linux_main and pal_start_thread should never return.
}
