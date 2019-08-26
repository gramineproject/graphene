/* Copyright (C) 2014 Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * db_rtld.c
 *
 * This file contains utilities to load ELF binaries into the memory
 * and link them against each other.
 * The source code in this file is imported and modified from the GNU C
 * Library.
 */

#include <api.h>
#include <pal_internal.h>

__asm__(".pushsection \".debug_gdb_scripts\", \"MS\",@progbits,1\r\n"
        ".byte 1\r\n"
        ".asciz \"" PAL_FILE("host/Linux-SGX/debugger/pal-gdb.py") "\"\r\n"
        ".popsection\r\n");

/* This function is hooked by our gdb integration script and should be
 * left as is. */
void load_gdb_command(const char* command) {
    __UNUSED(command);
}
