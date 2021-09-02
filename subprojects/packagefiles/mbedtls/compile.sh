#!/bin/sh

set -x
set -e

CURRENT_SOURCE_DIR="$1"
CURRENT_BUILD_DIR="$2"
PRIVATE_DIR="$3"
shift 3

OUTPUTS=""
while test "$#" -gt 0 && ! test "$1" = --
do
    OUTPUTS="$OUTPUTS $1"
    shift
done
if test "$1" = --
then
    shift
fi

rm -rf "$PRIVATE_DIR"

cp -ar "$CURRENT_SOURCE_DIR" "$PRIVATE_DIR"
patch -p1 --directory "$PRIVATE_DIR" <"$CURRENT_SOURCE_DIR"/graphene.patch

make -C "$PRIVATE_DIR" lib "$@"

for output in $OUTPUTS
do
    cp -a "$PRIVATE_DIR"/library/"$(basename "$output")" "$output"
done
