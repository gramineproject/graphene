#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) 2019  Wojtek Porczyk <woju@invisiblethingslab.com>

'''
Check ltp.cfg for tag sorting
'''

import argparse
import sys

argparser = argparse.ArgumentParser()
argparser.add_argument('config', metavar='FILENAME',
    type=argparse.FileType('r'), nargs='?', default='-',
    help='ltp.cfg file (default: stdin)')

def count_mistakes(file):
    mistakes = 0
    with file:
        prev = ''
        for i, line in enumerate(file):
            line = line.strip()
            if not line.startswith('['):
                continue
            line = line.strip(' []')
            if line < prev:
                print('bad order in line {i}: {line} (after {prev})'.format(
                    i=i, line=line, prev=prev))
                mistakes += 1
            prev = line
    return mistakes

def main(args=None):
    args = argparser.parse_args(args)
    return min(count_mistakes(args.config), 255)

if __name__ == '__main__':
    sys.exit(main())
