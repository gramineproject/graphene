#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later */
# Copyright (C) 2020 Intel Corporation
#                    Michał Kowalczyk <mkow@invisiblethingslab.com>

import os
import gdb  # pylint: disable=import-error

def main():
    gdb_script = os.path.dirname(__file__) + "/graphene.gdb"
    print("[%s] Loading %s..." % (os.path.basename(__file__), gdb_script))
    gdb.execute("source " + gdb_script)

if __name__ == '__main__':
    main()
