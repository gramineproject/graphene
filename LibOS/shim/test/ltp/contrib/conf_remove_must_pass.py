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
import enum
import sys

# textual config representation to preserve comments

argparser = argparse.ArgumentParser()
argparser.add_argument('--config', '-c', metavar='FILENAME',
    type=argparse.FileType('r'),
    default='-',
    help='location of ltp.cfg file')
argparser.add_argument('sections', metavar='SECTION',
    nargs='+',
    help='sections to be removed')

class State(enum.Enum):
    IDLE, ACCUMULATING, DROPPING = range(3)

def flush(accumulator):
    if accumulator and any(i.strip() for i in accumulator[1:]):
        for i in accumulator:
            sys.stdout.write(i)
    accumulator.clear()

def main(args=None):
    args = argparser.parse_args(args)

    with args.config as file:
        state = State.IDLE
        accumulator = []

        for line in file:
            if line.lstrip().startswith('['):
                section = line.strip(' \n[]')

                flush(accumulator)

                if section in args.sections:
                    state = State.ACCUMULATING
                else:
                    state = State.IDLE

            elif line.startswith('must-pass') and state is State.ACCUMULATING:
                state = State.DROPPING

            elif line[0] in ' \t':
                pass

            elif state is State.DROPPING:
                state = State.ACCUMULATING


            if state is State.IDLE:
                sys.stdout.write(line)
            elif state is State.ACCUMULATING:
                accumulator.append(line)

        flush(accumulator)


if __name__ == '__main__':
    main()
