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
 * db_rtld.c
 *
 * This file contains utilities to load ELF binaries into the memory
 * and link them against each other.
 * The source code in this file is imported and modified from the GNU C
 * Library.
 */

#include "pal_defs.h"
#include "pal_linux_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_debug.h"
#include "pal_error.h"
#include "pal_security.h"
#include "pal_rtld.h"
#include "api.h"

#include <sysdeps/generic/ldsodefs.h>
#include <elf/elf.h>
#include <bits/dlfcn.h>

#if USE_VDSO_GETTIME == 1
void setup_vdso_map (ElfW(Addr) addr)
{
    const ElfW(Ehdr) * header = (void *) addr;
    struct link_map * l = new_elf_object("vdso", OBJECT_RTLD);

    l->l_addr  = addr;
    l->l_entry = header->e_entry;
    l->l_phdr  = (void *) (addr + header->e_phoff);
    l->l_phnum = header->e_phnum;
    l->l_relocated = true;
    l->l_soname = "libpal.so";

    ElfW(Addr) load_offset = 0;
    const ElfW(Phdr) * ph;
    for (ph = l->l_phdr; ph < &l->l_phdr[l->l_phnum]; ++ph)
        switch (ph->p_type) {
            case PT_LOAD:
                load_offset = addr + (ElfW(Addr)) ph->p_offset
                              - (ElfW(Addr)) ph->p_vaddr;
                break;
            case PT_DYNAMIC:
                l->l_real_ld = l->l_ld = (void *) addr + ph->p_offset;
                l->l_ldnum = ph->p_memsz / sizeof (ElfW(Dyn));
                break;
        }

    ElfW(Dyn) local_dyn[4];
    int ndyn = 0;
    ElfW(Dyn) * dyn;
    for (dyn = l->l_ld ; dyn < &l->l_ld[l->l_ldnum]; ++dyn)
        switch(dyn->d_tag) {
            case DT_STRTAB:
            case DT_SYMTAB:
                local_dyn[ndyn] = *dyn;
                local_dyn[ndyn].d_un.d_ptr += load_offset;
                l->l_info[dyn->d_tag] = &local_dyn[ndyn++];
                break;
            case DT_HASH: {
                ElfW(Word) * h = (ElfW(Word) *) (D_PTR(dyn) + load_offset);
                l->l_nbuckets = h[0];
                l->l_buckets  = &h[2];
                l->l_chain    = &h[l->l_nbuckets + 2];
                break;
            }
            case DT_VERSYM:
            case DT_VERDEF:
                local_dyn[ndyn] = *dyn;
                local_dyn[ndyn].d_un.d_ptr += load_offset;
                l->l_info[VERSYMIDX(dyn->d_tag)] = &local_dyn[ndyn++];
                break;
        }

#if USE_CLOCK_GETTIME == 1
    const char * gettime = "__vdso_clock_gettime";
#else
    const char * gettime = "__vdso_gettimeofday";
#endif
    uint_fast32_t fast_hash = elf_fast_hash(gettime);
    long int hash = elf_hash(gettime);
    ElfW(Sym) * sym = NULL;

    sym = do_lookup_map(NULL, gettime, fast_hash, hash, l);
    if (sym)
#if USE_CLOCK_GETTIME == 1
        __vdso_clock_gettime =
#else
        __vdso_gettimeofday =
#endif
                (void *) (load_offset + sym->st_value);

    free(l);
}
#endif
