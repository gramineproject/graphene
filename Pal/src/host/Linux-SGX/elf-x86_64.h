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
 * dl-machine-x86_64.h
 *
 * This files contain architecture-specific implementation of ELF dynamic
 * relocation function.
 * The source code is imported and modified from the GNU C Library.
 */

#define ELF_MACHINE_NAME "x86_64"

#include <sysdep.h>
#include <sysdeps/generic/ldsodefs.h>

#include "pal_internal.h"

/* Return the link-time address of _DYNAMIC.  Conveniently, this is the
   first element of the GOT.  This must be inlined in a function which
   uses global data.  */
static inline Elf64_Addr __attribute__((unused)) elf_machine_dynamic(void) {
    /* This works because we have our GOT address available in the small PIC
       model.  */
    return (Elf64_Addr)&_DYNAMIC;
}

/* Return the run-time load address of the shared object.  */
static inline Elf64_Addr __attribute__((unused)) elf_machine_load_address(void) {
    Elf64_Addr addr;

    /* The easy way is just the same as on x86:
         leaq _dl_start, %0
         leaq _dl_start(%%rip), %1
         subq %0, %1
       but this does not work with binutils since we then have
       a R_X86_64_32S relocation in a shared lib.

       Instead we store the address of _dl_start in the data section
       and compare it with the current value that we can get via
       an RIP relative addressing mode.  Note that this is the address
       of _dl_start before any relocation performed at runtime.  In case
       the binary is prelinked the resulting "address" is actually a
       load offset which is zero if the binary was loaded at the address
       it is prelinked for.  */

    __asm__(
        "leaq " XSTRINGIFY(_ENTRY) "(%%rip), %0\n\t"
        "subq 1f(%%rip), %0\n\t"
        ".section\t.data.rel.ro\n"
        "1:\t.quad " XSTRINGIFY(_ENTRY) "\n\t"
        ".previous\n\t"
        : "=r"(addr)
        :
        : "cc");

    return addr;
}
