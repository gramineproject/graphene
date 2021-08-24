/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains architecture-independent macros of ELF dynamic relocation function.
 * The source code was imported from the GNU C Library and modified.
 */

#include "dl-machine.h"
#include "pal_rtld.h"

#define elf_dynamic_do_rel       elf_dynamic_do_rela
#define RELCOUNT_IDX             VERSYMIDX(DT_RELACOUNT)
#define Rel                      Rela
#define elf_machine_rel          elf_machine_rela
#define elf_machine_rel_relative elf_machine_rela_relative

#ifndef DO_ELF_MACHINE_REL_RELATIVE
#define DO_ELF_MACHINE_REL_RELATIVE(l, relative) \
    elf_machine_rel_relative(l, relative, (void*)(l->l_addr + relative->r_offset))
#endif

static void __attribute_unused elf_dynamic_do_rel(struct link_map* l, ElfW(Addr) reladdr,
                                                  int relsize) {
    if (!l->l_info[DT_SYMTAB])
        return;

    if (relsize == 0)
        return;

    ElfW(Rel)* r = (void*)reladdr, *end = (void*)(reladdr + relsize);
    ElfW(Sym)* symtab    = (void*)D_PTR(l->l_info[DT_SYMTAB]);
    ElfW(Word) nrelative = l->l_info[RELCOUNT_IDX] ? l->l_info[RELCOUNT_IDX]->d_un.d_val : 0;
    ElfW(Rel)* relative  = r;

    r = r + MIN(nrelative, relsize / sizeof(ElfW(Rel)));

#ifndef RTLD_BOOTSTRAP
    /* This is defined in rtld.c, but nowhere in the static libc.a; make
       the reference weak so static programs can still link.  This
       declaration cannot be done when compiling rtld.c (i.e. #ifdef
       RTLD_BOOTSTRAP) because rtld.c contains the common defn for
       _dl_rtld_map, which is incompatible with a weak decl in the same
       file.  */
#if !defined DO_RELA || defined ELF_MACHINE_REL_RELATIVE
    /* Rela platforms get the offset from r_addend and this must
       be copied in the relocation address.  Therefore we can skip
       the relative relocations only if this is for rel
       relocations or rela relocations if they are computed as
       memory_loc += l_addr...  */
    if (l->l_addr != 0)
#else
    /* ...or we know the object has been prelinked.  */
    if (l->l_addr != 0 || !l->l_info[VALIDX(DT_GNU_PRELINKED)])
#endif
#endif
        for (; relative < r; ++relative) {
            DO_ELF_MACHINE_REL_RELATIVE(l, relative);
        }

    for (; r < end; ++r) {
        elf_machine_rel(l, r, &symtab[ELFW(R_SYM)(r->r_info)], (void*)(l->l_addr + r->r_offset));
    }
}

#undef elf_dynamic_do_rel
#undef Rel
#undef elf_machine_rel
#undef elf_machine_rel_relative
#undef DO_ELF_MACHINE_REL_RELATIVE
#undef RELCOUNT_IDX
