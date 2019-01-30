#!/usr/bin/env bash

times=$1
[ $times -gt 0 2> /dev/null ] || times=300

for (( c=1; c<=$times; c++ ))
do
	echo "hello $c"
	cp somefile testdir/somefile
	rm -rf testdir/somefile
	ls testdir/
	cat somefile > testdir/x
	date
done > OUTPUT
