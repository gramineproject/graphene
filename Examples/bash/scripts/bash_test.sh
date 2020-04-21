#!/usr/bin/env bash

times=$1
[ $times -gt 0 2> /dev/null ] || times=300

for (( c=1; c<=$times; c++ ))
do
	echo "hello $c"
	cp somefile testdir/somefile
	echo "cp"
	cat somefile > testdir/createdfile
	echo "cat"
	ls testdir/
	echo "ls"
	rm -rf testdir/somefile testdir/createdfile
	echo "rm"
	date +"current date is %D"
	echo "date"
done
