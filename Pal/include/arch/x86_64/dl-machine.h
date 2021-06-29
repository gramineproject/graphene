/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains architecture-specific implementation of ELF dynamic relocation functions.
 * The source code was imported from the GNU C Library and modified.
 */

#ifndef DL_MACHINE_H
#define DL_MACHINE_H

#define ELF_MACHINE_NAME "x86_64"

#include "pal_internal.h"
#include "pal_rtld.h"
#include "sysdeps/generic/ldsodefs.h"

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
#define debug_reloc(r_type)                                                                 \
    do {                                                                                    \
        if (strtab && sym && sym->st_name)                                                  \
            log_debug("%p " #r_type ": %s %p", reloc_addr, strtab + sym->st_name, value);   \
        else if (value)                                                                     \
            log_debug("%p " #r_type ": %p", reloc_addr, value);                             \
        else                                                                                \
            log_debug("%p " #r_type, reloc_addr, value);                                    \
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
