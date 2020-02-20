#!/bin/bash
# $1 points to the root directory in which we search and hash everything
path=`realpath $1`
# $2 append output
output=$2

echo $0

# files excluding kernel and temporary files (+ itself + anything starting with .)
# also exclude utf-8 encoded file names (breaks signer)
find $path -not -type d | grep -v ^/boot | grep -v ^/dev | grep -v ^/proc | grep -v ^/var | grep -v ^/sys | grep -v ^$0 | grep -v ^/\\. | grep -v \/files | grep -Pv "[\x80-\xFF]" >files
#find $path -not -type d | grep -v ^/boot | grep -v ^/dev | grep -v ^/proc | grep -v ^/var | grep -v ^/sys | grep -v ^$0 | grep -v ^/\\. >files

# compute sha256 of each executable file
#if [ -x "$(command -v parallel)" ]; 
#then
#    cat files | parallel sha256sum &> sha.files
#else
#    cat files | xargs sha256sum &> sha.files
#fi

for f in $(cat files); 
do
    if [ -f $f ]
    then
        echo $f >> checkedfiles
    fi
done

# rewrite output to graphene manifest style
#cat sha.files | awk '{name=substr($2,2); gsub("/", "-", name); gsub(/\./, "-", name); printf "sgx.trusted_files.%s=%s\nsgx.trusted_checksum.%s.sha=%s\n", name, $2, name, $1}' >> $2 2>&1
#cat sha.files | awk '{name=substr($2,2); gsub("/", "_", name); gsub(/\./, "_", name); printf "sgx.trusted_files.file%d=file:%s\n", NR, $2}' >> $2 2>&1
cat checkedfiles | awk '{printf "sgx.trusted_files.file%d=file:%s\n", NR, $1}' >> $2 2>&1