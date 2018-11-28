#!/bin/bash

if [ $# -ne 2 ]
then
	echo "$0 <test name> <count>"
	exit 100
fi

cd opt/ltp/testcases/bin

for i in `seq 1 $2`
do 
	./pal_loader $1
	echo -e "\033[0;31m $i) The return code is $? \033[0m"
done;
