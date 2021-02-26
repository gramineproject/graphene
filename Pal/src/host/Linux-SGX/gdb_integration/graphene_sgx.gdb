# SPDX-License-Identifier: LGPL-3.0-or-later */
# Copyright (C) 2021 Intel Corporation
#                    Michał Kowalczyk <mkow@invisiblethingslab.com>
#                    Paweł Marczewski <pawel@invisiblethingslab.com>

# Graphene GDB configuration (Linux-SGX specific).

# Prevent the preloaded sgx_gdb.so from being preloaded to the debuggee.
set env LD_PRELOAD=

# Disable displaced stepping. Displaced stepping means GDB executes an out-of-line copy of an
# instruction, instead of the original instruction at breakpoint location. This does not work when
# the instruction in question is located in SGX enclave memory, and should be executed in enclave.
set displaced-stepping off

# CPUID/RDTSC SIGILL skipping. We want to silently pass SIGILLs caused by CPUID and RDTSC
# instructions to the application, but without silencing SIGILLs caused by other reasons.

# (This seems impossible to implement in Python, either by using event handlers or even executing
# raw commands with gdb.execute(). gdb.execute() doesn't support multiline commands, and instead
# blocks for input on the *user terminal*, not giving the script a chance to provide more lines.)

catch signal SIGILL
# break only on CPUID (0fa2) and RDTSC (0f31)
condition $bpnum *(uint16_t*)$rip == 0xa20f || *(uint16_t*)$rip == 0x310f
commands
    silent

    # If we don't disable pagination then successive prints from this handler (even despite it's
    # called for different events) will stop and prompt the user for continuation, which is really
    # annoying.
    push-pagination off

    if *(uint16_t*)$rip == 0xa20f
        echo [graphene_sgx.gdb] Passing SIGILL caused by CPUID to the enclave\n
    end
    if *(uint16_t*)$rip == 0x310f
        echo [graphene_sgx.gdb] Passing SIGILL caused by RDTSC to the enclave\n
    end

    pop-pagination
    continue
end
