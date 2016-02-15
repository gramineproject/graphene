#!/bin/bash

hash_method=sha384

mkdir -p .packed

file=$1
shift
dir=.packed
packfile=$dir/${file}.tar.gz

hash="$(echo $(for f in $@; do echo $f; done | sort))"

src=$(for f in $@; do
	prev_f=
	while [ "$f" != "$prev_f" ]; do
		for ext in c cpp S; do
			[ ! -f ${f}.${ext} ] || echo ${f}.${ext}
		done
		prev_f=$f
		f=${f%.*}
	done
done | sort)

git rev-parse --show-toplevel 1>/dev/null 2>/dev/null || not_in_git=1

hashfile=$dir/${file}.${hash_method}

[ "$src" == "" ] || hash="$hash $(cat ${src} | ${hash_method}sum | awk '{ print $1 }')"

if [ -f $hashfile ] && [ "$FORCE_PACK" != "1" ]; then
	if [ "$(cat $hashfile)" = "$hash" ]; then
		echo "Packed files are up-to-date, no need to repack the file."
		exit 0
	fi
fi

echo -n $hash > $hashfile
[ "$not_in_git" = "1" ] || git add $hashfile

tar -chzvvf $packfile $@
[ "$not_in_git" = "1" ] || git add $packfile
