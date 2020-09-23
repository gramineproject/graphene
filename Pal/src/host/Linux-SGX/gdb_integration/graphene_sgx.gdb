# SPDX-License-Identifier: LGPL-3.0-or-later */
# Copyright (C) 2020 Intel Corporation
#                    Michał Kowalczyk <mkow@invisiblethingslab.com>


# GDB Python "API" [1] is so wonderful that what we need [2] is not possible to be implemented using
# it, so we have to fall back to raw GDB scripting. But raw GDB scripting is also broken, so we need
# to supply things like `push-pagination` command from Python.
#
# [1] It mostly consists of `gdb.execute()`, there isn't even gdb.continue() API, you need to call
#     `gdb.execute('continue')`.
# [2] One of the things we want is to silently pass SIGILLs caused by CPUID and RDTSC to the
#     application, but without silencing SIGILLs caused by other reasons. This is impossible to
#     implement from GDB Python "API", neither using event handlers nor even executing raw commands
#     with gdb.execute() - it doesn't support multiline commands, and gdb.execute('commands') blocks
#     for input on the *user terminal*, not giving the script a chance to provide more lines.


# Prevent the preloaded sgx_gdb.so from being preloaded to the debuggee.
set env LD_PRELOAD=

# Tell Graphene to behave more gdb-friendly.
set env IN_GDB=1

# Used internally by Graphene, generates a lot of noise if we don't silence it.
handle SIGCONT pass noprint nostop

# TODO: This block of commands was copied from an older Graphene integration script where they
# didn't have any comments with rationale why they are needed. We should revise and comment them.
handle SIGKILL pass print stop
set disable-randomization off
set detach-on-fork off
set schedule-multiple on
set follow-exec-mode same
set follow-fork-mode child
set displaced-stepping off

# CPUID/RDTSC SIGILL skipping. See [2] above.

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
