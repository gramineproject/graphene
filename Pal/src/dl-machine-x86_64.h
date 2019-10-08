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

#ifndef DL_MACHINE_H
#define DL_MACHINE_H

#define ELF_MACHINE_NAME "x86_64"

#include <sysdeps/generic/ldsodefs.h>

#include "pal_internal.h"
#include "pal_rtld.h"

/* The x86-64 never uses Elf64_Rel relocations.  */
#define ELF_MACHINE_NO_REL 1

/* Perform the relocation specified by RELOC and SYM (which is fully resolved).
   MAP is the object containing the reloc.  */

//#define DEBUG_RELOC

static void elf_machine_rela(struct link_map* l, Elf64_Rela* reloc, Elf64_Sym* sym,
                             void* const reloc_addr_arg) {
    Elf64_Addr* const reloc_addr   = reloc_addr_arg;
    const unsigned long int r_type = ELF64_R_TYPE(reloc->r_info);

    const char* __attribute_unused strtab = (const void*)D_PTR(l->l_info[DT_STRTAB]);

#ifdef DEBUG_RELOC
#define debug_reloc(r_type)                                                              \
    do {                                                                                 \
        if (strtab && sym && sym->st_name)                                               \
            printf("%p " #r_type ": %s %p\n", reloc_addr, strtab + sym->st_name, value); \
        else if (value)                                                                  \
            printf("%p " #r_type ": %p\n", reloc_addr, value);                           \
        else                                                                             \
            printf("%p " #r_type "\n", reloc_addr, value);                               \
    } while (0)
#else
#define debug_reloc(...) \
    do {                 \
    } while (0)
#endif

    if (r_type == R_X86_64_RELATIVE) {
        /* This is defined in rtld.c, but nowhere in the static libc.a;
           make the reference weak so static programs can still link.
           This declaration cannot be done when compiling rtld.c
           (i.e. #ifdef RTLD_BOOTSTRAP) because rtld.c contains the
           common defn for _dl_rtld_map, which is incompatible with a
           weak decl in the same file.  */

        //*reloc_addr = l->l_addr + reloc->r_addend;
        return;
    }

    if (r_type == R_X86_64_NONE)
        return;

    Elf64_Addr value = l->l_addr + sym->st_value;
#ifndef RTLD_BOOTSTRAP
    struct link_map* sym_map = 0;

    if (sym->st_shndx == SHN_UNDEF) {
        value = RESOLVE_RTLD(strtab + sym->st_name);

        if (!value) {
            sym_map = RESOLVE_MAP(&strtab, &sym);
            if (!sym_map)
                return;

            assert(sym);
            value = sym_map->l_addr + sym->st_value;
        }

#if CACHE_LOADED_BINARIES == 1
        if (!sym_map || sym_map->l_type == OBJECT_RTLD) {
            assert(l->nrelocs < NRELOCS);
            l->relocs[l->nrelocs++] = reloc_addr;
        }
#endif
    }
#endif

    if (ELFW(ST_TYPE)(sym->st_info) == STT_GNU_IFUNC && sym->st_shndx != SHN_UNDEF)
        value = ((Elf64_Addr(*)(void))value)();

    /* In the libc loader, they guaranteed that only R_ARCH_RELATIVE,
       R_ARCH_GLOB_DAT, R_ARCH_JUMP_SLOT appear in ld.so. We observed
       the same thing in libpal.so, so we are gonna to make the same
       assumption */
    switch (r_type) {
        case R_X86_64_GLOB_DAT:
            debug_reloc(R_X86_64_GLOB_DAT);
            *reloc_addr = value + reloc->r_addend;
            break;

        case R_X86_64_JUMP_SLOT:
            debug_reloc(R_X86_64_JUMP_SLOT);
            *reloc_addr = value + reloc->r_addend;
            break;

#ifndef RTLD_BOOTSTRAP
        case R_X86_64_64:
            debug_reloc(R_X86_64_64);
            *reloc_addr = value + reloc->r_addend;
            break;

        case R_X86_64_32:
            debug_reloc(R_X86_64_32);
            value += reloc->r_addend;
            *(Elf64_Addr*)reloc_addr = value;
            break;

        /* Not needed for dl-conflict.c.  */
        case R_X86_64_PC32:
            debug_reloc(R_X86_64_PC32);
            value += reloc->r_addend - (Elf64_Addr)reloc_addr;
            *(Elf64_Addr*)reloc_addr = value;
            break;

        case R_X86_64_IRELATIVE:
            debug_reloc(R_X86_64_IRELATIVE);
            value       = sym_map->l_addr + reloc->r_addend;
            value       = ((Elf64_Addr(*)(void))value)();
            *reloc_addr = value;
            break;
#endif
        default:
            return;
    }

#ifndef RTLD_BOOTSTRAP
    /* We have relocated the symbol, we don't want the
       interpreter to relocate it again. */
    reloc->r_info ^= ELF64_R_TYPE(reloc->r_info);
#endif
}

static void elf_machine_rela_relative(struct link_map* l, const Elf64_Rela* reloc,
                                      void* const reloc_addr_arg) {
    Elf64_Addr* const reloc_addr = reloc_addr_arg;
    assert(ELF64_R_TYPE(reloc->r_info) == R_X86_64_RELATIVE);
    *reloc_addr = l->l_addr + reloc->r_addend;
}

#endif /* !DL_MACHINE_H */
