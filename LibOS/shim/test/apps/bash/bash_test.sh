#!/bin/bash
times=$1
rm -rf OUTPUT
[ $times -gt 0 2> /dev/null ] || times=300
time for (( c=1; c<=$times; c++ ))
do
echo "hello $c" >> OUTPUT
cp somefile ./testdir/somefile
rm -rf ./testdir/somefile
ls ./testdir/ >> OUTPUT
cat somefile > ./testdir/x
date >> OUTPUT
done

#cleanup
rm ./testdir/x
