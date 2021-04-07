#!/bin/sh

set -e

if test -n "$SGX"
then
    GRAPHENE=graphene-sgx
else
    GRAPHENE=graphene-direct
fi

for i in `ls "$DATA_DIR"/scenes/`;
do
    rm -f "$DATA_DIR"/images/"$i"0001.png
    $GRAPHENE "../blender" -b /data/scenes/$i -t 4 -F PNG -o /data/images/$i -f 1
    # TODO add a better test, probably some diff with a precomputed image
    [ -f "$DATA_DIR"/images/"$i"0001.png ]
done
