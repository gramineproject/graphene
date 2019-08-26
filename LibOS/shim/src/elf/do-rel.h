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
 * do-rel.c
 *
 * This file contains architecture-independent codes for relocating ELF
 * binaries.
 * Most of the source codes are imported from GNU C library.
 */

#include "dl-machine-x86_64.h"

#define elf_dynamic_do_rel       elf_dynamic_do_rela
#define RELCOUNT_IDX             VERSYMIDX(DT_RELACOUNT)
#define Rel                      Rela
#define elf_machine_rel          elf_machine_rela
#define elf_machine_rel_relative elf_machine_rela_relative
#define elf_dynamic_redo_rel     elf_dynamic_redo_rela

#ifndef DO_ELF_MACHINE_REL_RELATIVE
#define DO_ELF_MACHINE_REL_RELATIVE(l, relative) \
    elf_machine_rel_relative(l, relative, (void*)((l)->l_addr + relative->r_offset))
#endif

#ifndef VERSYMIDX
#define VERSYMIDX(sym) (DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGIDX(sym))
#endif

#ifndef VALIDX
#define VALIDX(tag) (DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM + DT_EXTRANUM + DT_VALTAGIDX(tag))
#endif

#define elf_dynamic_copy_rel elf_dynamic_copy_rela
#define dt_reloc             DT_RELA
#define dt_reloc_sz          DT_RELASZ

/* Perform the relocations in MAP on the running program image as specified
   by RELTAG, SZTAG.  If LAZY is nonzero, this is the first pass on PLT
   relocations; they should be set up to call _dl_runtime_resolve, rather
   than fully resolved now.  */
static void __attribute__((unused))
elf_dynamic_do_rel(struct link_map* l, ElfW(Addr) reladdr, size_t relsize) {
    if (!l->l_info[DT_SYMTAB])
        return;

    ElfW(Sym)* symtab = (void*)D_PTR(l->l_info[DT_SYMTAB]);
    ElfW(Rel)* r      = (void*)reladdr;
    ElfW(Rel)* end    = (void*)(reladdr + relsize);
    ElfW(Word) nrelative =
        l->l_info[RELCOUNT_IDX] == NULL ? 0 : l->l_info[RELCOUNT_IDX]->d_un.d_val;
    size_t nrelsize = relsize / sizeof(ElfW(Rel));

    r = r + (nrelative < nrelsize ? nrelative : nrelsize);
    for (; r < end; ++r) {
        ElfW(Sym)* sym = &symtab[ELFW(R_SYM)(r->r_info)];
        void* reloc    = (void*)l->l_addr + r->r_offset;
        if (elf_machine_rel(l, r, sym, reloc)) {
            assert(l->nlinksyms < MAX_LINKSYMS);
            l->linksyms[l->nlinksyms].rel   = r;
            l->linksyms[l->nlinksyms].sym   = sym;
            l->linksyms[l->nlinksyms].reloc = reloc;
            l->nlinksyms++;
        }
    }
}

static void __attribute__((unused)) elf_dynamic_redo_rel(struct link_map* l) {
    for (int i = 0; i < l->nlinksyms; i++)
        elf_machine_rel(l, l->linksyms[i].rel, l->linksyms[i].sym, l->linksyms[i].reloc);
}

#if 0
static void inline elf_copy_rel (struct link_map * l1, struct link_map * l2,
                                 int reloc, int reloc_sz)
{
    if (!l1->l_info[reloc] || !l2->l_info[reloc])
        return;

    ElfW(Sym) *  symtab1 = (void *) D_PTR (l1->l_info[DT_SYMTAB]);
    const char * strtab1 = (void *) D_PTR (l1->l_info[DT_STRTAB]);
    ElfW(Sym) *  symtab2 = (void *) D_PTR (l2->l_info[DT_SYMTAB]);
    const char * strtab2 = (void *) D_PTR (l2->l_info[DT_STRTAB]);

    ElfW(Rel) * r1, * r2, * end1, * end2;

    r1 = (ElfW(Rel) *) D_PTR (l1->l_info[reloc]);
    end1 = ((void *) r1 + l1->l_info[reloc_sz]->d_un.d_val);
    r1 += l1->l_info[RELCOUNT_IDX] ? l1->l_info[RELCOUNT_IDX]->d_un.d_val : 0;

    r2 = (ElfW(Rel) *) D_PTR (l2->l_info[reloc]);
    end2 = ((void *) r2 + l2->l_info[reloc_sz]->d_un.d_val);
    r2 += l2->l_info[RELCOUNT_IDX] ? l2->l_info[RELCOUNT_IDX]->d_un.d_val : 0;

    for (; r1 < end1 && r2 < end2; ++r1, ++r2) {
        debug("copy %s from %s\n",
              strtab1 + symtab1[ELFW(R_SYM) (r1->r_info)].st_name,
              strtab2 + symtab2[ELFW(R_SYM) (r2->r_info)].st_name);

        r1->r_info = r2->r_info;

        ElfW(Addr) * reladdr1 = (void *) l1->l_addr + r1->r_offset;
        ElfW(Addr) * reladdr2 = (void *) l2->l_addr + r2->r_offset;

        if (*reladdr1 != *reladdr2)
            *reladdr1 = *reladdr2;
    }
}

/* copy the relocation done by PAL */
static void __attribute__((unused))
elf_dynamic_copy_rel (struct link_map * l1, struct link_map * l2)
{
    elf_copy_rel(l1, l2, dt_reloc, dt_reloc_sz);
    elf_copy_rel(l1, l2, DT_JMPREL, DT_PLTRELSZ);
}
#endif

#undef elf_dynamic_do_rel
#undef Rel
#undef elf_machine_rel
#undef elf_machine_rel_relative
#undef DO_ELF_MACHINE_REL_RELATIVE
#undef RELCOUNT_IDX
//#undef elf_dynamic_copy_rel
#undef dt_reloc
#undef dt_reloc_sz
#undef elf_dynamic_redo_rel
