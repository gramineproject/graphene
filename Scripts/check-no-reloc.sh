#!/bin/sh

test $# -eq 1 || exit 2

if ! LC_ALL=C readelf -r "$1" | grep -q 'There are no relocations in this file.'
then
    # print to stdout
    LC_ALL=C readelf -r "$1"
    exit 1
fi
