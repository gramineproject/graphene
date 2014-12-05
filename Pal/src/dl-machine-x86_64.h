/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2014 OSCAR lab, Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * dl-machine-x86_64.h
 *
 * This files contain architecture-specific implementation of ELF dynamic
 * relocation function.
 * The source code is imported and modified from the GNU C Library.
 */

#ifndef dl_machine_h
#define dl_machine_h

#define ELF_MACHINE_NAME "x86_64"

#include <sys/param.h>
#include <sysdep.h>
#include <sysdeps/generic/ldsodefs.h>
#include "pal_internal.h"

/* The x86-64 never uses Elf64_Rel relocations.  */
#define ELF_MACHINE_NO_REL 1

/* Perform the relocation specified by RELOC and SYM (which is fully resolved).
   MAP is the object containing the reloc.  */

//#define DEBUG_RELOC

static void
elf_machine_rela (Elf64_Dyn **l_info, Elf64_Addr l_addr,
                  Elf64_Rela *reloc, Elf64_Sym *sym, void *const reloc_addr_arg,
                  bool rel, bool rel_relative)
{
    Elf64_Addr *const reloc_addr = reloc_addr_arg;
    const unsigned long int r_type = ELF64_R_TYPE (reloc->r_info);

    const char * __attribute__ ((unused)) strtab =
                            (const void *) D_PTR (l_info[DT_STRTAB]);

#ifdef DEBUG_RELOC
#define elf_machine_rela_debug(r_type, sym, value)                  \
    ({  if (strtab && sym && sym->st_name)                          \
            printf(#r_type ": %s\n", strtab + sym->st_name);        \
        else if (value)                                             \
            printf(#r_type ": %p\n", value);                        \
        else                                                        \
            printf(#r_type "\n", value);                            \
    })
#else
#define elf_machine_rela_debug(...) ({})
#endif

    if (__builtin_expect (r_type == R_X86_64_RELATIVE, 0))
    {
        /* This is defined in rtld.c, but nowhere in the static libc.a;
           make the reference weak so static programs can still link.
           This declaration cannot be done when compiling rtld.c
           (i.e. #ifdef RTLD_BOOTSTRAP) because rtld.c contains the
           common defn for _dl_rtld_map, which is incompatible with a
           weak decl in the same file.  */

        if (rel_relative)
        {
#ifndef RTLD_BOOTSTRAP
            elf_machine_rela_debug (R_X86_64_RELATIVE, sym, 0);
            *reloc_addr = l_addr + reloc->r_addend;
#endif
        }
        return;
    }

    if (__builtin_expect (r_type == R_X86_64_NONE, 0))
    {
        elf_machine_rela_debug (R_X86_64_NONE, sym, 0);
        return;
    }

#ifdef RTLD_BOOTSTRAP
    Elf64_Addr value = (sym == NULL ? 0 : l_addr + sym->st_value);
#define SYM (sym)
#else
    Elf64_Sym *refsym = sym;
    Elf64_Addr value;
    Elf64_Addr sym_map = 0;

    value = RESOLVE_RTLD(strtab + sym->st_name);

    if (value) {
        /* We can't handle a IRELEATIVE symbol if it's found in RTLD,
           they should never exist */
        if (r_type == R_X86_64_IRELATIVE)
            return;
    } else {
        sym_map = RESOLVE_MAP(&strtab, &sym) ? : l_addr;
        value = sym_map + (sym ? sym->st_value : refsym->st_value);
    }

#define SYM (sym ? : refsym)

    /* We do a very special relocation for loaded libraries */
    if (!rel) {
        if (sym && refsym && refsym != sym) {
            refsym->st_info = sym->st_info;
            refsym->st_size = sym->st_size;

            if (__builtin_expect (ELFW(ST_TYPE) (sym->st_info)
                                  == STT_GNU_IFUNC, 0)
                && __builtin_expect (sym->st_shndx != SHN_UNDEF, 1))
            {
                value = ((Elf64_Addr (*) (void)) value) ();

                refsym->st_info ^= ELFW(ST_TYPE)(sym->st_info);
                refsym->st_info |= STT_FUNC;
            }

            refsym->st_value = value - l_addr;
        } else {
            return;
        }
    }
#endif

    if (sym != NULL
        && __builtin_expect (ELFW(ST_TYPE) (sym->st_info)
                             == STT_GNU_IFUNC, 0)
        && __builtin_expect (sym->st_shndx != SHN_UNDEF, 1))
        value = ((Elf64_Addr (*) (void)) value) ();

    /* In the libc loader, they guaranteed that only R_ARCH_RELATIVE,
       R_ARCH_GLOB_DAT, R_ARCH_JUMP_SLOT appear in ld.so. We observed
       the same thing in libpal.so, so we are gonna to make the same
       assumption */
    switch (r_type)
    {
        case R_X86_64_GLOB_DAT:
            elf_machine_rela_debug (R_X86_64_GLOB_DAT, SYM, value);
            *reloc_addr = value + reloc->r_addend;
            break;

        case R_X86_64_JUMP_SLOT:
            elf_machine_rela_debug (R_X86_64_JUMP_SLOT, SYM, value);
            *reloc_addr = value + reloc->r_addend;
            break;

#ifndef RTLD_BOOTSTRAP
        case R_X86_64_64:
            elf_machine_rela_debug (R_X86_64_64, SYM, value);
            *reloc_addr = value + reloc->r_addend;
            break;

        case R_X86_64_32:
            elf_machine_rela_debug (R_X86_64_32, SYM, value);
            value += reloc->r_addend;
            *(Elf64_Addr *) reloc_addr = value;
            break;

        /* Not needed for dl-conflict.c.  */
        case R_X86_64_PC32:
            elf_machine_rela_debug (R_X86_64_PC32, SYM, value);
            value += reloc->r_addend - (Elf64_Addr) reloc_addr;
            *(Elf64_Addr *) reloc_addr = value;
            break;

        case R_X86_64_COPY:
            elf_machine_rela_debug (R_X86_64_COPY, SYM, value);
            size_t sym_size = sym ? sym->st_size : 0;
            size_t ref_size = refsym ? refsym->st_size : 0;
            memcpy (reloc_addr_arg, (void *) value, MIN (sym_size,
                    ref_size));
            break;

        case R_X86_64_IRELATIVE:
            elf_machine_rela_debug (R_X86_64_IRELATIVE, SYM, value);
            value = sym_map + reloc->r_addend;
            value = ((Elf64_Addr (*) (void)) value) ();
            *reloc_addr = value;
            break;
#endif
        default:
            return;
    }

    if (!rel)
        /* We have relocated the symbol, we don't want the
           interpreter to relocate it again. */
        reloc->r_info ^= ELF64_R_TYPE (reloc->r_info);
}

static void
elf_machine_rela_relative (Elf64_Addr l_addr, const Elf64_Rela *reloc,
                           void *const reloc_addr_arg)
{
    Elf64_Addr *const reloc_addr = reloc_addr_arg;
    assert (ELF64_R_TYPE (reloc->r_info) == R_X86_64_RELATIVE);
    *reloc_addr = l_addr + reloc->r_addend;
}

#endif /* !dl_machine_h */
