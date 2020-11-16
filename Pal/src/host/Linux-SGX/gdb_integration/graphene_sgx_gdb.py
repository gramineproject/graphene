# SPDX-License-Identifier: LGPL-3.0-or-later */
# Copyright (C) 2020 Intel Corporation
#                    Michał Kowalczyk <mkow@invisiblethingslab.com>
#                    Paweł Marczewski <pawel@invisiblethingslab.com>

import os

import gdb # pylint: disable=import-error


_g_paginations = []


def retrieve_debug_maps():
    '''
    Retrieve the debug_map structure from the inferior process. The result is a dict with the
    following structure:

    {load_addr: (file_name, {name: addr})}
    '''

    if int(gdb.parse_and_eval('g_pal_enclave.debug_map')) == 0:
        # Not initialized yet
        return {}

    debug_maps = {}
    val_map = gdb.parse_and_eval('*g_pal_enclave.debug_map')
    while int(val_map) != 0:
        file_name = val_map['file_name'].string()
        file_name = os.path.abspath(file_name)

        load_addr = int(val_map['load_addr'])

        sections = {}
        val_section = val_map['section']
        while int(val_section) != 0:
            name = val_section['name'].string()
            addr = int(val_section['addr'])

            sections[name] = addr
            val_section = val_section['next']

        # We need the text_addr to use add-symbol-file (at least until GDB 8.2).
        if '.text' in sections:
            debug_maps[load_addr] = (file_name, sections)

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
        for load_addr in set(old) | set(new):
            # Skip unload/reload if the map is unchanged
            if old.get(load_addr) == new.get(load_addr):
                continue

            # Note that this doesn't escape the file names.

            if load_addr in old:
                # Log the removing, because remove-symbol-file itself doesn't produce helpful output
                # on errors.
                file_name, sections = old[load_addr]
                print("Removing symbol file (was {}) from addr: 0x{:x}".format(
                    file_name, load_addr))
                try:
                    gdb.execute('remove-symbol-file -a 0x{:x}'.format(load_addr))
                except gdb.error:
                    print('warning: failed to remove symbol file')

            if load_addr in new:
                file_name, sections = new[load_addr]
                text_addr = sections['.text']
                cmd = 'add-symbol-file {} 0x{:x} '.format(file_name, text_addr)
                cmd += ' '.join('-s {} 0x{:x}'.format(name, addr)
                                for name, addr in sections.items()
                                if name != '.text')
                gdb.execute(cmd)

        progspace.sgx_debug_maps = new


class PushPagination(gdb.Command):
    """Temporarily changing pagination and saving the old state.

    Supplements gdb interface with functionality it's missing and seems to not be possible to
    implement from a gdb script. This command is used by graphene_sgx.gdb script.
    """

    def __init__(self):
        super().__init__("push-pagination", gdb.COMMAND_USER)

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
        super().__init__("pop-pagination", gdb.COMMAND_USER)

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


def clear_objfiles_handler(event):
    # Record that symbol files has been cleared on GDB's side (e.g. on program exit), so that we do
    # not try to remove them again.
    if hasattr(event.progspace, 'sgx_debug_maps'):
        delattr(event.progspace, 'sgx_debug_maps')


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
    gdb.events.clear_objfiles.connect(clear_objfiles_handler)

if __name__ == "__main__":
    main()
