# SPDX-License-Identifier: LGPL-3.0-or-later */
# Copyright (C) 2020 Intel Corporation
#                    Michał Kowalczyk <mkow@invisiblethingslab.com>

import os

import gdb # pylint: disable=import-error

# pylint: disable=no-self-use,too-few-public-methods

_g_paginations = []

class PushPagination(gdb.Command):
    """Temporarily changing pagination and saving the old state.

    Supplements gdb interface with functionality it's missing and seems to not be possible to
    implement from a gdb script. This command is used by graphene_sgx.gdb script.
    """

    def __init__(self):
        super(PushPagination, self).__init__("push-pagination", gdb.COMMAND_USER)

    def invoke(self, arg, _from_tty):
        self.dont_repeat()

        pagination_str = gdb.execute('show pagination', to_string=True).strip()
        assert pagination_str in ('State of pagination is on.', 'State of pagination is off.')
        pagination = pagination_str.endswith('on.')
        _g_paginations.append(pagination)

        assert arg in ('on', 'off')
        gdb.execute('set pagination ' + arg)


class PopPagination(gdb.Command):
    """Recover pagination state saved by PushPagination"""

    def __init__(self):
        super(PopPagination, self).__init__("pop-pagination", gdb.COMMAND_USER)

    def invoke(self, arg, _from_tty):
        self.dont_repeat()

        assert arg == ''
        pagination = _g_paginations.pop()
        gdb.execute('set pagination ' + ('on' if pagination else 'off'))


class LoadCommandBreakpoint(gdb.Breakpoint):
    def __init__(self):
        gdb.Breakpoint.__init__(self, spec="execute_gdb_command", internal=1)

    def stop(self):
        command = gdb.parse_and_eval("(const char*)$rdi").string()
        gdb.execute(command)
        return False

def main():
    PushPagination()
    PopPagination()

    # Some of the things we want to do can't be done using gdb Python API, we need to fall back to a
    # standard gdb script.
    gdb_script = os.path.dirname(__file__) + "/graphene_sgx.gdb"
    print("[%s] Loading %s..." % (os.path.basename(__file__), gdb_script))
    gdb.execute("source " + gdb_script)

    LoadCommandBreakpoint()

if __name__ == "__main__":
    main()
