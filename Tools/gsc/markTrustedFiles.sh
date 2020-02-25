#!/bin/bash
# $1 points to the root directory in which we search and hash everything
path=`realpath $1`
# $2 append output
output=$2

echo $0

# files excluding kernel and temporary files (+ itself + anything starting with .)
# also exclude utf-8 encoded file names (breaks signer)
find $path -not -type d | grep -v ^/boot | grep -v ^/dev | grep -v ^/proc | grep -v ^/var | grep -v ^/sys | grep -v /etc/rc | grep -v ^$0 | grep -v ^/\\. | grep -v \/files | grep -Pv "[\x80-\xFF]" >files


for f in $(cat files); 
do
    if [ -f $f ]
    then
        echo $f >> checkedfiles
    fi
done

# rewrite output to graphene manifest style
cat checkedfiles | awk '{printf "sgx.trusted_files.file%d=file:%s\n", NR, $1}' >> $2 2>&1