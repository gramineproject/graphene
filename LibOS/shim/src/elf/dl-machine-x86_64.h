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
 * dl-machine-x86_64.c
 *
 * This file contains x64-specific codes for relocating ELF binaries.
 * Most of the source codes are imported from GNU C library.
 */

#ifndef __DL_MACHINE_H__
#define __DL_MACHINE_H__

#define ELF_MACHINE_NAME "x86_64"

#include "ldsodefs.h"

/* Return nonzero iff ELF header is compatible with the running host.  */
static inline int __attribute__((unused)) elf_machine_matches_host(const Elf64_Ehdr* ehdr) {
    return ehdr->e_machine == EM_X86_64;
}

/* ELF_RTYPE_CLASS_PLT iff TYPE describes relocation of a PLT entry or
   TLS variable, so undefined references should not be allowed to
   define the value.
   ELF_RTYPE_CLASS_NOCOPY iff TYPE should not be allowed to resolve to one
   of the main executable's symbols, as for a COPY reloc.  */
#define elf_machine_type_class(type) \
    ((((type) == R_X86_64_JUMP_SLOT  \
    || (type) == R_X86_64_DTPMOD64   \
    || (type) == R_X86_64_DTPOFF64   \
    || (type) == R_X86_64_TPOFF64    \
    || (type) == R_X86_64_TLSDESC)   \
    * ELF_RTYPE_CLASS_PLT)           \
    | (((type) == R_X86_64_COPY) * ELF_RTYPE_CLASS_COPY))

/* The x86-64 never uses Elf64_Rel relocations.  */
#define ELF_MACHINE_NO_REL 1

/* Perform the relocation specified by RELOC and SYM (which is fully resolved).
   MAP is the object containing the reloc.  */

//#define DEBUG_RELOC

static bool elf_machine_rela(struct link_map* l, ElfW(Rela) * reloc, Elf64_Sym* sym,
                             void* const reloc_addr_arg) {
    Elf64_Addr* const reloc_addr   = reloc_addr_arg;
    const unsigned long int r_type = ELF64_R_TYPE(reloc->r_info);

    const char* __attribute__((unused)) strtab = (const void*)D_PTR(l->l_info[DT_STRTAB]);

#ifdef DEBUG_RELOC
#define debug_reloc(r_type, sym, value)                       \
    ({                                                        \
        if (strtab && (sym) && (sym)->st_name)                \
            debug(#r_type ": %s\n", strtab + (sym)->st_name); \
        else if (value)                                       \
            debug(#r_type ": %p\n", (value));                 \
        else                                                  \
            debug(#r_type "\n", (value));                     \
    })
#else
#define debug_reloc(...) ({})
#endif

    if (r_type == R_X86_64_RELATIVE || r_type == R_X86_64_NONE)
        return false;

    Elf64_Sym* refsym = sym;
    Elf64_Addr value;
    Elf64_Addr sym_map = RESOLVE_MAP(&strtab, &sym);

    if (!sym_map || !sym || refsym == sym)
        return false;

    value = sym_map + sym->st_value;

    /* We do a very special relocation for loaded libraries */
    PROTECT_PAGE(l, refsym, sizeof(*refsym));
    PROTECT_PAGE(l, reloc_addr, sizeof(*reloc_addr));

    refsym->st_info = sym->st_info;
    refsym->st_size = sym->st_size;

    if (ELFW(ST_TYPE)(sym->st_info) == STT_GNU_IFUNC && sym->st_shndx != SHN_UNDEF) {
        value = ((Elf64_Addr(*)(void))value)();

        refsym->st_info ^= ELFW(ST_TYPE)(sym->st_info);
        refsym->st_info |= STT_FUNC;
    }

    debug_reloc("shim symbol", sym, value);

    refsym->st_value = value - l->l_addr;
    *reloc_addr      = value + ((r_type == R_X86_64_GLOB_DAT || r_type == R_X86_64_JUMP_SLOT ||
                            r_type == R_X86_64_64)
                               ? reloc->r_addend
                               : 0);

    /* We have relocated the symbol, we don't want the
       interpreter to relocate it again. */
    if (r_type != R_X86_64_NONE) {
        PROTECT_PAGE(l, reloc, sizeof(*reloc));
        reloc->r_info = (reloc->r_info ^ ELF64_R_TYPE(reloc->r_info)) | R_X86_64_NONE;
    }

    return true;
}

#endif /* !DL_MACHINE_H */
