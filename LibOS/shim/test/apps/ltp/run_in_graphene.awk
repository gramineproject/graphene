#!/usr/bin/awk -f
#
#    Script for adding necessary valgrind calls before commands.
#
#    Copyright (C) 2016 Stony Brook University.
#    This file is part of Graphene library OS.
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU Lesser General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Chia-Che Tsai, Fall 2016
#
NF && ! /^#/ && ! /epoll/ {
	s=$1 "_graphene ./pal_loader"
	for (i = 2; i <= NF; i++) {
		s = s " " $i
	}
	print s
}
