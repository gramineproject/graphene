#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later */
# Copyright (C) 2020 Intel Corporation
#                    Michał Kowalczyk <mkow@invisiblethingslab.com>

set -eu -o pipefail

# Arguments: binaries for which to generate manifest trusted files list.

# Be careful: We have to skip vdso, which doesn't have a corresponding file on the disk (we assume
# that such files have paths starting with '/', seems ldd aways prints absolute paths). Also, old
# ldd (from Ubuntu 16.04) prints vdso differently than newer ones:
# old:
#     linux-vdso.so.1 =>  (0x00007ffd31fee000)
# new:
#     linux-vdso.so.1 (0x00007ffd31fee000)
DEPS=$(ldd "$@" \
	| awk '{
		if ($2 == "=>" && $3 ~ /^\/.*$/) {
			print $3
		} else if ($1 ~ /^\/.*$/ && $2 ~ /^\(.+\)$/) {
			print $1
		}
	}' \
	| sort | uniq)

for DEP in $DEPS; do
	# generate Graphene manifest line
	echo "sgx.trusted_files.\"$DEP\" = \"file:$DEP\""
done
