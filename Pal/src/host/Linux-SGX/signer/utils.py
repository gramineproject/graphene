# Copyright (C) 2019 Intel Corporation
#                    Isaku Yamahata <isaku.yamahata at gmail.com>
#                                   <isaku.yamahata at intel.com>
# All Rights Reserved
# This file is part of Graphene Library OS.
#
# Graphene Library OS is free software: you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# Graphene Library OS is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

""" Utilities """

def int_to_bytes(i):
    b = bytearray()
    l = 0
    while i > 0:
        b.append(i % 256)
        i = i // 256
        l = l + 1
    return b


def bytes_to_int_big(b):
    i = 0
    for c in b:
        i = i * 256 + c
    return i


bytes_to_int = bytes_to_int_big


def bytes_to_int_little(bytes):
    i = 0
    q = 1
    for digit in bytes:
        if digit != 0:
            i = i + digit * q
        q = q * 256
    return i


def parse_int(s):
    if len(s) > 2 and s.startswith("0x"):
        return int(s[2:], 16)
    if len(s) > 1 and s.startswith("0"):
        return int(s[1:], 8)
    return int(s)


def parse_size(s):
    scale = 1
    if s.endswith("K"):
        scale = 1024
    if s.endswith("M"):
        scale = 1024 * 1024
    if s.endswith("G"):
        scale = 1024 * 1024 * 1024
    if scale != 1:
        s = s[:-1]
    return parse_int(s) * scale
