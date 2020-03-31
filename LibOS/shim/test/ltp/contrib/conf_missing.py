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
import configparser
import sys

argparser = argparse.ArgumentParser()
argparser.add_argument('--config', '-c', metavar='FILENAME',
    type=argparse.FileType('r'),
    help='location of ltp.cfg file')
argparser.add_argument('file', metavar='FILENAME',
    type=argparse.FileType('r'), nargs='?', default='-',
    help='LTP scenario file')

def main(args=None):
    args = argparser.parse_args(args)
    config = configparser.ConfigParser()
    config.read_file(args.config)

    with args.file:
        for line in args.file:
            line = line.strip()
            if not line or line[0] == '#': continue

            tag, cmd = line.split(maxsplit=1)
            if not tag in config and not any(c in cmd for c in '|;&'):
                print(f'[{tag}]\nmust-pass =\n')

if __name__ == '__main__':
    main()
