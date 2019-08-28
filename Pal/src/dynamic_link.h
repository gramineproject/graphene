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
 * dynamic_link.h
 *
 * This files contain inline functions for dynamic linking.
 * The source code is imported and modified from the GNU C Library.
 */

#include <dl-machine-x86_64.h>
#include <elf/elf.h>
#include <pal_internal.h>
#include <pal_rtld.h>

/* We pass reloc_addr as a pointer to void, as opposed to a pointer to
   ElfW(Addr), because not all architectures can assume that the
   relocated address is properly aligned, whereas the compiler is
   entitled to assume that a pointer to a type is properly aligned for
   the type.  Even if we cast the pointer back to some other type with
   less strict alignment requirements, the compiler might still
   remember that the pointer was originally more aligned, thereby
   optimizing away alignment tests or using word instructions for
   copying memory, breaking the very code written to handle the
   unaligned cases.  */
#if !ELF_MACHINE_NO_REL
static inline void __attribute_always_inline elf_machine_rel(struct link_map* l, ElfW(Rel)* reloc,
                                                             ElfW(Sym)* sym,
                                                             void* const reloc_addr);

static inline void __attribute_always_inline elf_machine_rel_relative(struct link_map* l,
                                                                      const ElfW(Rel)* reloc,
                                                                      void* const reloc_addr);
#endif

#if !ELF_MACHINE_NO_RELA
static inline void __attribute_always_inline elf_machine_rela(struct link_map* l,
                                                              ElfW(Rela)* reloc, ElfW(Sym)* sym,
                                                              void* const reloc_addr);

static inline void __attribute_always_inline elf_machine_rela_relative(struct link_map* l,
                                                                       const ElfW(Rela)* reloc,
                                                                       void* const reloc_addr);
#endif

/* Read the dynamic section at DYN and fill in INFO with indices DT_*.  */
static inline void __attribute_unused __attribute_always_inline
elf_get_dynamic_info(ElfW(Dyn)* dyn, ElfW(Dyn)** l_info, ElfW(Addr) l_addr) {
#if __ELF_NATIVE_CLASS == 32
    typedef Elf32_Word d_tag_utype;
#elif __ELF_NATIVE_CLASS == 64
    typedef Elf64_Xword d_tag_utype;
#endif

#ifndef RTLD_BOOTSTRAP
    if (dyn == NULL)
        return;
#endif

    while (dyn->d_tag != DT_NULL) {
        d_tag_utype dt_extranum = DT_EXTRANUM;

        if ((d_tag_utype)dyn->d_tag < DT_NUM)
            l_info[dyn->d_tag] = dyn;

        else if (dyn->d_tag >= DT_LOPROC && dyn->d_tag < DT_LOPROC + DT_THISPROCNUM)
            l_info[dyn->d_tag - DT_LOPROC + DT_NUM] = dyn;

        else if ((d_tag_utype)DT_VERSIONTAGIDX(dyn->d_tag) < DT_VERSIONTAGNUM)
            l_info[VERSYMIDX(dyn->d_tag)] = dyn;

        else if ((d_tag_utype)DT_EXTRATAGIDX(dyn->d_tag) < dt_extranum)
            l_info[DT_EXTRATAGIDX(dyn->d_tag) + DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM] = dyn;

        else if ((d_tag_utype)DT_VALTAGIDX(dyn->d_tag) < DT_VALNUM)
            l_info[DT_VALTAGIDX(dyn->d_tag) + DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM +
                   DT_EXTRANUM] = dyn;

        else if ((d_tag_utype)DT_ADDRTAGIDX(dyn->d_tag) < DT_ADDRNUM)
            l_info[DT_ADDRTAGIDX(dyn->d_tag) + DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM +
                   DT_EXTRANUM + DT_VALNUM] = dyn;

        ++dyn;
    }

    if (l_addr != 0) {
#define ADJUST_DYN_INFO(tag)                   \
    do {                                       \
        if (l_info[tag])                       \
            l_info[tag]->d_un.d_ptr += l_addr; \
    } while (0);

        ADJUST_DYN_INFO(DT_HASH);
        ADJUST_DYN_INFO(DT_PLTGOT);
        ADJUST_DYN_INFO(DT_STRTAB);
        ADJUST_DYN_INFO(DT_SYMTAB);

#if !ELF_MACHINE_NO_RELA
        ADJUST_DYN_INFO(DT_RELA);
#endif

#if !ELF_MACHINE_NO_REL
        ADJUST_DYN_INFO(DT_REL);
#endif

        ADJUST_DYN_INFO(DT_JMPREL);
        ADJUST_DYN_INFO(VERSYMIDX(DT_VERSYM));
        ADJUST_DYN_INFO(DT_ADDRTAGIDX(DT_GNU_HASH) + DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM +
                        DT_EXTRANUM + DT_VALNUM);
#undef ADJUST_DYN_INFO
    }

    /* Then a bunch of assertion, we could kind of ignore them */
    if (l_info[DT_PLTREL]) {
#if ELF_MACHINE_NO_RELA
        assert(l_info[DT_PLTREL]->d_un.d_val == DT_REL);

#elif ELF_MACHINE_NO_REL
        assert(l_info[DT_PLTREL]->d_un.d_val == DT_RELA);

#else
        assert(l_info[DT_PLTREL]->d_un.d_val == DT_REL || l_info[DT_PLTREL]->d_un.d_val == DT_RELA);
#endif
    }

#if !ELF_MACHINE_NO_RELA
    if (l_info[DT_RELA])
        assert(l_info[DT_RELAENT]->d_un.d_val == sizeof(ElfW(Rela)));
#endif

#if !ELF_MACHINE_NO_REL
    if (l_info[DT_REL])
        assert(l_info[DT_RELENT]->d_un.d_val == sizeof(ElfW(Rel)));
#endif

#ifdef RTLD_BOOTSTRAP
    /* Only the bind now flags are allowed.  */
    assert(!l_info[VERSYMIDX(DT_FLAGS_1)] || l_info[VERSYMIDX(DT_FLAGS_1)]->d_un.d_val == DF_1_NOW);
    assert(!l_info[DT_FLAGS] || l_info[DT_FLAGS]->d_un.d_val == DF_BIND_NOW);
    /* Flags must not be set for ld.so.  */
    assert(!l_info[DT_RUNPATH]);
    assert(!l_info[DT_RPATH]);
#endif
}

#ifdef RTLD_BOOTSTRAP
#define ELF_DURING_STARTUP (1)
#else
#define ELF_DURING_STARTUP (0)
#endif

/* Get the definitions of `elf_dynamic_do_rel' and `elf_dynamic_do_rela'.
   These functions are almost identical, so we use cpp magic to avoid
   duplicating their code.  It cannot be done in a more general function
   because we must be able to completely inline.  */

/* On some machines, notably SPARC, DT_REL* includes DT_JMPREL in its
   range.  Note that according to the ELF spec, this is completely legal!
   But conditionally define things so that on machines we know this will
   not happen we do something more optimal.  */

#ifdef ELF_MACHINE_PLTREL_OVERLAP
/* ELF_MACHINE_PLTREL_OVERLAP is only used for s390, powerpc and sparc.
   We will keep it for now */

static void _elf_dynamic_do_reloc(struct link_map* l, int dt_reloc, int dt_reloc_sz,
                                  void (*do_reloc)(struct link_map*, ElfW(Addr), int)) {
    struct {
        ElfW(Addr) start, size;
    } ranges[3];
    int ranges_index;

    ranges[0].size = ranges[1].size = ranges[2].size = 0;

    if (l->l_info[dt_reloc]) {
        ranges[0].start = D_PTR(l->l_info[dt_reloc]);
        ranges[0].size  = l->l_info[dt_reloc_sz]->d_un.d_val;
    }

    for (ranges_index = 0; ranges_index < 3; ++ranges_index)
        (*do_reloc)(l, ranges[ranges_index].start, ranges[ranges_index].size);
}
#else
/* Now this part is for our x86s machines */

static void __attribute_unused _elf_dynamic_do_reloc(struct link_map* l, uint64_t dt_reloc,
                                                     int dt_reloc_sz,
                                                     void (*do_reloc)(struct link_map*, ElfW(Addr),
                                                                      int)) {
    struct {
        ElfW(Addr) start, size;
    } ranges[2];
    ranges[0].size = ranges[1].size = 0;
    ranges[0].start = ranges[1].start = 0;

    if (l->l_info[dt_reloc]) {
        ranges[0].start = D_PTR(l->l_info[dt_reloc]);
        ranges[0].size = l->l_info[dt_reloc_sz]->d_un.d_val;
    }

    if (l->l_info[DT_PLTREL] && l->l_info[DT_PLTREL]->d_un.d_val == dt_reloc) {
        ElfW(Addr) start = D_PTR(l->l_info[DT_JMPREL]);

        if (!ELF_DURING_STARTUP &&
            /* This test does not only detect whether the relocation
               sections are in the right order, it also checks whether
               there is a DT_REL/DT_RELA section.  */
            ranges[0].start + ranges[0].size != start) {
            ranges[1].start = start;
            ranges[1].size = l->l_info[DT_PLTRELSZ]->d_un.d_val;
        } else {
            /* Combine processing the sections.  */
            assert(ranges[0].start + ranges[0].size == start);
            ranges[0].size += l->l_info[DT_PLTRELSZ]->d_un.d_val;
        }
    }

    /* This is interesting, don't make it lazy. */
    if (ELF_DURING_STARTUP) {
        (*do_reloc)(l, ranges[0].start, ranges[0].size);
    } else {
        int ranges_index;
        for (ranges_index = 0; ranges_index < 2; ++ranges_index)
            (*do_reloc)(l, ranges[ranges_index].start, ranges[ranges_index].size);
    }
}
#endif

#define _ELF_DYNAMIC_DO_RELOC(RELOC, reloc, l) \
    _elf_dynamic_do_reloc(l, DT_##RELOC, DT_##RELOC##SZ, &elf_dynamic_do_##reloc)

#if ELF_MACHINE_NO_REL || ELF_MACHINE_NO_RELA
#define _ELF_CHECK_REL 0
#else
#define _ELF_CHECK_REL 1
#endif

#if !ELF_MACHINE_NO_REL
#include "do-rel.h"
#define ELF_DYNAMIC_DO_REL(l) _ELF_DYNAMIC_DO_RELOC(REL, rel, l)
#else
/* nothing to do */
#define ELF_DYNAMIC_DO_REL(l)
#endif

#if !ELF_MACHINE_NO_RELA
#define DO_RELA
#include "do-rel.h"
#define ELF_DYNAMIC_DO_RELA(l) _ELF_DYNAMIC_DO_RELOC(RELA, rela, l)
#else
/* nothing to do */
#define ELF_DYNAMIC_DO_RELA(l)
#endif

/* This can't just be an inline function because GCC is too dumb
   to inline functions containing inlines themselves.  */
#define ELF_DYNAMIC_RELOCATE(l) \
    do {                        \
        ELF_DYNAMIC_DO_REL(l);  \
        ELF_DYNAMIC_DO_RELA(l); \
    } while (0)
