#!/usr/bin/env python3

#
# Copyright (C) 2019  Wojtek Porczyk <woju@invisiblethingslab.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

import argparse
import collections
import sys

DEFAULT = 'DEFAULT'

# textual config representation to preserve comments

argparser = argparse.ArgumentParser()
argparser.add_argument('files', metavar='FILENAME',
    type=argparse.FileType('r'),
    nargs='+',
    help='.cfg files to be merged')

def print_section(section, lines):
    if section is not None:
        print(f'[{section}]')
    for line in lines:
        print(line, end='')

def main(args=None):
    args = argparser.parse_args(args)
    sections = collections.defaultdict(list)

    for file in args.files:
        section = None

        with file:
            for line in file:
                if line.lstrip().startswith('['):
                    section = line.strip(' \n[]')
                else:
                    sections[section].append(line)

    for section in (None, DEFAULT):
        if section not in sections:
            continue
        print_section(section, sections.pop(section))

    for section in sorted(sections):
        print_section(section, sections[section])

if __name__ == '__main__':
    main()
