#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2021 Intel Corporation
#                    Wojtek Porczyk <woju@invisiblethingslab.com>
#

r'''
Convert inline assembly into preprocessor directives.
The source line is something like::

    .ascii "GENERATED_INTEGER SHIM_TCB_OFF $8 "

(see the DEFINE macro in common/include/generated-offsets-build.h)

Because of clang compatibility, we need to:
- generate the numbers with prefix ($) and strip it here, as clang doesn't support "%p"
  in inline assembly
- recognize both tab and space [ \t] after ".ascii"
'''

import abc
import argparse
import re

regex = re.compile(r'''
    \s*
    \.ascii \s+ "GENERATED_INTEGER \s+
    (?P<name>\w+) \s+
    \$?(?P<offset>\d+)
    \s*"
    \s*
''', re.VERBOSE)

class AbstractOutput(metaclass=abc.ABCMeta):
    def __init__(self, file):
        self.file = file

    @classmethod
    def make_type(cls, filetype):
        def func(*args, **kwds):
            return cls(filetype(*args, **kwds))
        return func

    @abc.abstractmethod
    def write_preamble(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def write_footer(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def write_offset(self, name, offset):
        raise NotImplementedError()

class OutputHeader(AbstractOutput):
    def write_preamble(self):
        self.file.write('''\
/* DO NOT MODIFY. THIS FILE WAS AUTO-GENERATED. */
#ifndef ASM_OFFSETS_H_
#define ASM_OFFSETS_H_

''')

    def write_footer(self):
        self.file.write('''
#endif /* ASM_OFFSETS_H_ */
''')

    def write_offset(self, name, offset):
        self.file.write(f'''\
#ifndef {name}
#define {name} {offset}
#endif
''')

class OutputPython(AbstractOutput):
    def write_preamble(self):
        self.file.write('''\
# DO NOT MODIFY. THIS FILE WAS AUTO-GENERATED.

''')

    def write_footer(self):
        pass

    def write_offset(self, name, offset):
        self.file.write(f'{name} = {offset}\n')


argparser = argparse.ArgumentParser()
argparser.add_argument('--output-h',
    type=OutputHeader.make_type(argparse.FileType('w')),
    action='append',
    dest='outputs',
)
argparser.add_argument('--output-py',
    type=OutputPython.make_type(argparse.FileType('w')),
    action='append',
    dest='outputs',
)
argparser.add_argument('infile', type=argparse.FileType('r'))
argparser.set_defaults(outputs=[])

def main(args=None):
    args = argparser.parse_args(args)

    for output in args.outputs:
        output.write_preamble()

    for line in args.infile:
        match = regex.fullmatch(line.rstrip('\n'))
        if not match:
            continue
        name, offset = match.group('name'), match.group('offset')
        for output in args.outputs:
            output.write_offset(name, offset)

    for output in args.outputs:
        output.write_footer()


if __name__ == '__main__':
    main()
