# SPDX-License-Identifier: LGPL-3.0-or-later */
# Copyright (C) 2020 Intel Corporation
#                    Michał Kowalczyk <mkow@invisiblethingslab.com>
#                    Paweł Marczewski <pawel@invisiblethingslab.com>

import os

import gdb # pylint: disable=import-error

# pylint: disable=no-self-use,too-few-public-methods

_g_paginations = []


def retrieve_debug_maps():
    '''
    Retrieve the debug_map structure from the inferior process. The result is a dict with the
    following structure:

    {file_name: (text_addr, {name: addr})}
    '''

    debug_maps = {}
    val_map = gdb.parse_and_eval('*g_pal_enclave.debug_map')
    while int(val_map) != 0:
        file_name = val_map['file_name'].string()
        file_name = os.path.abspath(file_name)

        text_addr = int(val_map['text_addr'])

        sections = {}
        val_section = val_map['section']
        while int(val_section) != 0:
            name = val_section['name'].string()
            addr = int(val_section['addr'])

            sections[name] = addr
            val_section = val_section['next']

        debug_maps[file_name] = (text_addr, sections)
        val_map = val_map['next']

    return debug_maps


class UpdateDebugMaps(gdb.Command):
    """Update debug maps for the inferior process."""

    def __init__(self):
        super().__init__('update-debug-maps', gdb.COMMAND_USER)

    def invoke(self, arg, _from_tty):
        self.dont_repeat()
        assert arg == ''

        # Store the currently loaded maps inside the Progspace object, so that we can compare
        # old and new states. See:
        # https://sourceware.org/gdb/current/onlinedocs/gdb/Progspaces-In-Python.html
        progspace = gdb.current_progspace()
        if not hasattr(progspace, 'sgx_debug_maps'):
            progspace.sgx_debug_maps = {}

        old = progspace.sgx_debug_maps
        new = retrieve_debug_maps()
        for file_name in set(old) | set(new):
            # Skip unload/reload if the map is unchanged
            if old.get(file_name) == new.get(file_name):
                continue

            # Note that this doesn't escape the file names.

            if file_name in old:
                # Remove the file by address, not by name, because:
                #
                # 1. the names are resolved by gdb when loading, so even though we call
                #    os.path.abspath() on our names, gdb might not recognize our name,
                # 2. the same file (such as libc.so) might be loaded both inside and outside the
                #    enclave, and we don't want to remove both instances, only the one that we
                #    added.
                #
                # In addition, log the removing, because remove-symbol-file itself doesn't produce
                # helpful output on errors.
                text_addr, _sections = old[file_name]
                print("Removing symbol file {} at addr: 0x{:x}".format(file_name, text_addr))
                gdb.execute('remove-symbol-file -a 0x{:x}'.format(text_addr))

            if file_name in new:
                text_addr, sections = new[file_name]
                cmd = 'add-symbol-file {} 0x{:x} '.format(file_name, text_addr)
                cmd += ' '.join('-s {} 0x{:x}'.format(name, addr)
                                for name, addr in sections.items())
                gdb.execute(cmd)

        progspace.sgx_debug_maps = new


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


class UpdateBreakpoint(gdb.Breakpoint):
    def __init__(self):
        gdb.Breakpoint.__init__(self, spec="update_debugger", internal=1)

    def stop(self):
        gdb.execute('update-debug-maps')
        return False


def stop_handler(_event):
    # Make sure we handle connecting to a new process correctly:
    # update the debug maps if we never did it before.
    progspace = gdb.current_progspace()
    if not hasattr(progspace, 'sgx_debug_maps'):
        gdb.execute('update-debug-maps')


def main():
    PushPagination()
    PopPagination()
    UpdateDebugMaps()

    # Some of the things we want to do can't be done using gdb Python API, we need to fall back to a
    # standard gdb script.
    gdb_script = os.path.dirname(__file__) + "/graphene_sgx.gdb"
    print("[%s] Loading %s..." % (os.path.basename(__file__), gdb_script))
    gdb.execute("source " + gdb_script)

    UpdateBreakpoint()
    gdb.events.stop.connect(stop_handler)

if __name__ == "__main__":
    main()
