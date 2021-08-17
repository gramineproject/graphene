# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) 2021 Invisible Things Lab
#                    Michał Kowalczyk <mkow@invisiblethingslab.com>

# Commands for temporarily changing source language. Used by other Graphene GDB scripts to ensure
# that a specific source language is used for parsing expressions - GDB interprets scripts using
# the language taken from currently executing code, which may change in time, resulting in scripts
# working only part of the time.
#
# Example: When a GDB script does `if *(uint16_t*)$rip == 0x1234` in a signal catchpoint then it
# will fail with a syntax error if the binary debugged is written in Rust, but only if the signal
# arrived while executing Rust code.

import gdb # pylint: disable=import-error

_g_languages = []

def cut_between(src, before, after):
    start = src.index(before) + len(before)
    return src[start:src.index(after, start)]


class PushLanguage(gdb.Command):
    """Temporarily change source language and save the old one"""

    def __init__(self):
        super().__init__('push-language', gdb.COMMAND_USER)

    def invoke(self, arg, _from_tty):
        self.dont_repeat()

        lang_str = gdb.execute('show language', to_string=True).strip()
        lang_str = cut_between(lang_str, 'The current source language is "', '"')
        if ';' in lang_str:  # for things like 'auto; currently c'
            lang_str = lang_str[:lang_str.index(';')]
        _g_languages.append(lang_str)

        gdb.execute('set language ' + arg)


class PopLanguage(gdb.Command):
    """Recover source language saved by PushLanguage"""

    def __init__(self):
        super().__init__('pop-language', gdb.COMMAND_USER)

    def invoke(self, arg, _from_tty):
        self.dont_repeat()

        assert arg == ''
        lang = _g_languages.pop()
        gdb.execute('set language ' + lang)


def main():
    PushLanguage()
    PopLanguage()


if __name__ == '__main__':
    main()
