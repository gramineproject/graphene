#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later */
# Copyright (C) 2020 Intel Corporation
#                    Michał Kowalczyk <mkow@invisiblethingslab.com>

set -e

# Arguments: binaries for which to generate manifest trusted files list.

# Be careful: We have to skip vdso, which doesn't have a corresponding file on the disk (we assume
# that such files have paths starting with '/', seems ldd aways prints absolute paths).
DEPS=$(ldd "$@" \
	| awk '{
		if ($2 == "=>") {
			print $3
		} else if ($1 ~ /^\/.*$/ && $2 ~ /^\(.+\)$/) {
			print $1
		}
	}' \
	| sort | uniq)

for DEP in $DEPS; do
	# remove special characters (resulting IDs are quite ugly, but good enough)
	ID=$(echo $DEP | tr -c -d "[:alnum:]_")

	# generate Graphene manifest line
	echo "sgx.trusted_files.$ID = \"file:$DEP\""
done
