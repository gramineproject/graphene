# SPDX-License-Identifier: LGPL-3.0-or-later */
# Copyright (C) 2020 Intel Corporation
#                    Michał Kowalczyk <mkow@invisiblethingslab.com>

# Tell Graphene to behave more gdb-friendly.
set env IN_GDB=1

# Used internally by Graphene, generates a lot of noise if we don't silence it.
handle SIGCONT pass noprint nostop

# TODO: This block of commands was copied from an older Graphene integration script where they
# didn't have any comments with rationale why they are needed. We should revise and comment them.
set auto-load off
handle SIGKILL pass print stop
set disable-randomization off
set detach-on-fork off
set schedule-multiple on
set follow-fork-mode child

break pal_start
command
    silent
    set scheduler-locking off
    continue
end

break thread_start
command
    silent
    continue
end

catch vfork
command
    silent
    set scheduler-locking on
    continue
end
