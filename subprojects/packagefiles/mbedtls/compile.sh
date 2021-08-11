#!/bin/sh

# TODO Debug/Release

set -x
set -e

pwd >&2

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
    input=$(basename "$output" | sed -e 's:_[a-z]*::')
    cp -a "$PRIVATE_DIR"/library/"$input" "$output"
done
