# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) 2020 Intel Corporation
#                    Michał Kowalczyk <mkow@invisiblethingslab.com>
#                    Paweł Marczewski <pawel@invisiblethingslab.com>

import os

import gdb # pylint: disable=import-error

def main():
    for filename in [
            'common/language_gdb.py',
            'common/pagination_gdb.py',
            'common/debug_map_gdb.py',
            'common/graphene.gdb',
            'graphene_sgx.gdb',
    ]:
        print('[%s] Loading %s...' % (os.path.basename(__file__), filename))
        path = os.path.join(os.path.dirname(__file__), filename)
        gdb.execute('source ' + path)


if __name__ == '__main__':
    main()
