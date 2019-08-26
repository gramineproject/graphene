#include "elf.h"

#ifndef VERSYMIDX
#define VERSYMIDX(sym) (DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGIDX(sym))
#endif

#ifndef DT_THISPROCNUM
#define DT_THISPROCNUM 0
#endif

#if __ELF_NATIVE_CLASS == 32
typedef Elf32_Word d_tag_utype, d_val_utype;
#elif __ELF_NATIVE_CLASS == 64
typedef Elf64_Xword d_tag_utype, d_val_utype;
#endif

#define IN_RANGE(l, addr) \
    ((ElfW(Addr))(addr) >= (l)->l_map_start && (ElfW(Addr))(addr) < (l)->l_map_end)

#define RELOCATE(l, addr)                                          \
    ((__typeof__(addr))(IN_RANGE((l), (addr)) ? (ElfW(Addr))(addr) \
                                              : (ElfW(Addr))(addr) + (ElfW(Addr))((l)->l_addr)))

#ifdef __x86_64__
#include "dl-machine-x86_64.h"
#endif

/* Read the dynamic section at DYN and fill in INFO with indices DT_*.  */
static inline void __attribute__((unused, always_inline)) elf_get_dynamic_info(struct link_map* l) {
    ElfW(Dyn)* dyn = l->l_ld;

    if (dyn == NULL)
        return;

    while (dyn->d_tag != DT_NULL) {
        int tag = 0;

        if ((d_tag_utype)dyn->d_tag < DT_NUM)
            tag = dyn->d_tag;

        else if (dyn->d_tag >= DT_LOPROC && dyn->d_tag < DT_LOPROC + DT_THISPROCNUM)
            tag = dyn->d_tag - DT_LOPROC + DT_NUM;

        else if ((d_tag_utype)DT_VERSIONTAGIDX(dyn->d_tag) < DT_VERSIONTAGNUM)
            tag = VERSYMIDX(dyn->d_tag);

        else if ((d_tag_utype)DT_EXTRATAGIDX(dyn->d_tag) < DT_EXTRANUM)
            tag = DT_EXTRATAGIDX(dyn->d_tag) + DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM;

        else if ((d_tag_utype)DT_VALTAGIDX(dyn->d_tag) < DT_VALNUM)
            tag =
                DT_VALTAGIDX(dyn->d_tag) + DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM + DT_EXTRANUM;

        else if ((d_tag_utype)DT_ADDRTAGIDX(dyn->d_tag) < DT_ADDRNUM)
            tag = DT_ADDRTAGIDX(dyn->d_tag) + DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM +
                  DT_EXTRANUM + DT_VALNUM;

        if (tag)
            l->l_info[tag] = dyn;

        ++dyn;
    }

    if (l->l_addr) {
#define ADJUST_DYN_INFO(tag)                                                      \
    do {                                                                          \
        if (l->l_info[tag] != NULL) {                                             \
            l->l_info[tag]->d_un.d_ptr = RELOCATE(l, l->l_info[tag]->d_un.d_ptr); \
            /* debug("relocate info[%d] = %p\n",                                  \
                  tag, l->l_info[tag]->d_un.d_ptr); */                            \
        }                                                                         \
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
    if (l->l_info[DT_PLTREL] != NULL) {
#if ELF_MACHINE_NO_RELA
        assert(l->l_info[DT_PLTREL]->d_un.d_val == DT_REL);

#elif ELF_MACHINE_NO_REL
        assert(l->l_info[DT_PLTREL]->d_un.d_val == DT_RELA);

#else
        assert(l->l_info[DT_PLTREL]->d_un.d_val == DT_REL ||
               l->l_info[DT_PLTREL]->d_un.d_val == DT_RELA);
#endif
    }

#if !ELF_MACHINE_NO_RELA
    if (l->l_info[DT_RELA] != NULL)
        assert(l->l_info[DT_RELAENT]->d_un.d_val == sizeof(ElfW(Rela)));
#endif

#if !ELF_MACHINE_NO_REL
    if (l->l_info[DT_REL] != NULL)
        assert(l->l_info[DT_RELENT]->d_un.d_val == sizeof(ElfW(Rel)));
#endif
}

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

static void _elf_dynamic_do_reloc(struct link_map* l, d_val_utype dt_reloc, d_val_utype dt_reloc_sz,
                                  void (*do_reloc)(struct link_map*, ElfW(Addr), size_t)) {
    struct {
        ElfW(Addr) start, size;
    } ranges[3];

    ranges[0].size = ranges[1].size = ranges[2].size = 0;

    if (l->l_info[dt_reloc]) {
        ranges[0].start = D_PTR(l->l_info[dt_reloc]);
        ranges[0].size  = l->l_info[dt_reloc_sz]->d_un.d_val;
    }

    for (int ranges_index = 0; ranges_index < 3; ++ranges_index)
        (*do_reloc)(l, ranges[ranges_index].start, ranges[ranges_index].size);
}
#else
/* Now this part is for our x86s machines */

static void __attribute__((unused))
_elf_dynamic_do_reloc(struct link_map* l, d_val_utype dt_reloc, d_val_utype dt_reloc_sz,
                      void (*do_reloc)(struct link_map*, ElfW(Addr), size_t)) {
    struct {
        ElfW(Addr) start, size;
    } ranges[2];
    ranges[0].size = ranges[1].size = 0;
    ranges[0].start = ranges[1].start = 0;

    if (l->l_info[dt_reloc]) {
        ranges[0].start = D_PTR(l->l_info[dt_reloc]);
        ranges[0].size  = l->l_info[dt_reloc_sz]->d_un.d_val;
    }

    if (l->l_info[DT_PLTREL] && l->l_info[DT_PLTREL]->d_un.d_val == dt_reloc) {
        ElfW(Addr) start = D_PTR(l->l_info[DT_JMPREL]);

        /* This test does not only detect whether the relocation
           sections are in the right order, it also checks whether
           there is a DT_REL/DT_RELA section.  */
        if (ranges[0].start + ranges[0].size != start) {
            ranges[1].start = start;
            ranges[1].size  = l->l_info[DT_PLTRELSZ]->d_un.d_val;
        } else {
            /* Combine processing the sections.  */
            assert(ranges[0].start + ranges[0].size == start);
            ranges[0].size += l->l_info[DT_PLTRELSZ]->d_un.d_val;
        }
    }

    for (int ranges_index = 0; ranges_index < 2; ++ranges_index)
        (*do_reloc)(l, ranges[ranges_index].start, ranges[ranges_index].size);
}
#endif

#define _ELF_DYNAMIC_DO_RELOC(RELOC, reloc, l) \
    _elf_dynamic_do_reloc(l, DT_##RELOC, DT_##RELOC##SZ, &elf_dynamic_do_##reloc)
#define _ELF_DYNAMIC_REDO_RELOC(RELOC, reloc, l) elf_dynamic_redo_##reloc(l)

#if ELF_MACHINE_NO_REL || ELF_MACHINE_NO_RELA
#define _ELF_CHECK_REL 0
#else
#define _ELF_CHECK_REL 1
#endif

#if !ELF_MACHINE_NO_REL
#include "do-rel.h"
#define ELF_DYNAMIC_DO_REL(l)        _ELF_DYNAMIC_DO_RELOC(REL, rel, l)
#define ELF_DYNAMIC_COPY_REL(l1, l2) elf_dynamic_copy_rel(l1, l2)
#define ELF_DYNAMIC_REDO_REL(l)      _ELF_DYNAMIC_REDO_RELOC(REL, rel, l)
#else
/* nothing to do */
#define ELF_DYNAMIC_DO_REL(l)
//# define ELF_DYNAMIC_COPY_REL(l1, l2)
#define ELF_DYNAMIC_REDO_REL(l)
#endif

#if !ELF_MACHINE_NO_RELA
#define DO_RELA
#include "do-rel.h"
#define ELF_DYNAMIC_DO_RELA(l) _ELF_DYNAMIC_DO_RELOC(RELA, rela, l)
//# define ELF_DYNAMIC_COPY_RELA(l1, l2) elf_dynamic_copy_rela(l, l2)
#define ELF_DYNAMIC_REDO_RELA(l) _ELF_DYNAMIC_REDO_RELOC(RELA, rela, l)
#else
/* nothing to do */
#define ELF_DYNAMIC_DO_RELA(l)
//# define ELF_DYNAMIC_COPY_RELA(l1, l2)
#define ELF_DYNAMIC_REDO_RELA(l)
#endif

/* This can't just be an inline function because GCC is too dumb
   to inline functions containing inlines themselves.  */
#define ELF_DYNAMIC_RELOCATE(l) \
    do {                        \
        ELF_DYNAMIC_DO_REL(l);  \
        ELF_DYNAMIC_DO_RELA(l); \
    } while (0)

#if 0
#define ELF_DYNAMIC_COPY(l1, l2)       \
    do {                               \
        ELF_DYNAMIC_COPY_REL(l1, l2);  \
        ELF_DYNAMIC_COPY_RELA(l1, l2); \
    } while (0)
#endif

#define ELF_REDO_DYNAMIC_RELOCATE(l) \
    do {                             \
        ELF_DYNAMIC_REDO_REL(l);     \
        ELF_DYNAMIC_REDO_RELA(l);    \
    } while (0)
