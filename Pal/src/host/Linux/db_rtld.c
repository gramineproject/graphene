/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains host-specific code related to linking and reporting ELFs to debugger.
 *
 * Overview of ELF files used in this host:
 * - libpal.so - used as main executable, so it doesn't need to be reported separately
 * - LibOS, application, libc... - reported through DkDebugMap*
 */

#include "api.h"
#include "cpu.h"
#include "debug_map.h"
#include "elf-arch.h"
#include "elf/elf.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_rtld.h"

uintptr_t g_vdso_start = 0;
uintptr_t g_vdso_end = 0;

bool is_in_vdso(uintptr_t addr) {
    return (g_vdso_start || g_vdso_end) && g_vdso_start <= addr && addr < g_vdso_end;
}

void _DkDebugMapAdd(const char* name, void* addr) {
    int ret = debug_map_add(name, addr);
    if (ret < 0)
        log_error("debug_map_add(%s, %p) failed: %d", name, addr, ret);
}

void _DkDebugMapRemove(void* addr) {
    int ret = debug_map_remove(addr);
    if (ret < 0)
        log_error("debug_map_remove(%p) failed: %d", addr, ret);
}

void setup_pal_map(struct link_map* pal_map) {
    const ElfW(Ehdr)* header = (void*)pal_map->l_addr;

    pal_map->l_real_ld = pal_map->l_ld = (void*)elf_machine_dynamic();
    pal_map->l_type    = OBJECT_RTLD;
    pal_map->l_entry   = header->e_entry;
    pal_map->l_phdr    = (void*)(pal_map->l_addr + header->e_phoff);
    pal_map->l_phnum   = header->e_phnum;
    setup_elf_hash(pal_map);

    pal_map->l_prev = pal_map->l_next = NULL;
    g_loaded_maps = pal_map;
}

void setup_vdso_map(ElfW(Addr) addr) {
    const ElfW(Ehdr)* header = (void*)addr;
    struct link_map vdso_map;

    memset(&vdso_map, 0, sizeof(struct link_map));
    vdso_map.l_name  = "vdso";
    vdso_map.l_type  = OBJECT_RTLD;
    vdso_map.l_addr  = addr;
    vdso_map.l_entry = header->e_entry;
    vdso_map.l_phdr  = (void*)(addr + header->e_phoff);
    vdso_map.l_phnum = header->e_phnum;

    ElfW(Addr) load_offset = 0;
    const ElfW(Phdr) * ph;
    unsigned long pt_loads_count = 0;
    for (ph = vdso_map.l_phdr; ph < &vdso_map.l_phdr[vdso_map.l_phnum]; ph++)
        switch (ph->p_type) {
            case PT_LOAD:
                load_offset = addr + (ElfW(Addr))ph->p_offset - (ElfW(Addr))ph->p_vaddr;
                g_vdso_start = (uintptr_t)addr;
                g_vdso_end = ALIGN_UP(g_vdso_start + (size_t)ph->p_memsz, PAGE_SIZE);
                pt_loads_count++;
                break;
            case PT_DYNAMIC:
                vdso_map.l_real_ld = vdso_map.l_ld = (void*)addr + ph->p_offset;
                vdso_map.l_ldnum = ph->p_memsz / sizeof(ElfW(Dyn));
                break;
        }

    if (pt_loads_count != 1) {
        log_warning("The VDSO has %lu PT_LOAD segments, but only 1 was expected.", pt_loads_count);
        g_vdso_start = 0;
        g_vdso_end = 0;
        return;
    }

    ElfW(Dyn) local_dyn[4];
    int ndyn = 0;
    ElfW(Dyn) * dyn;
    for (dyn = vdso_map.l_ld; dyn < &vdso_map.l_ld[vdso_map.l_ldnum]; dyn++)
        switch(dyn->d_tag) {
            case DT_STRTAB:
            case DT_SYMTAB:
                local_dyn[ndyn] = *dyn;
                local_dyn[ndyn].d_un.d_ptr += load_offset;
                vdso_map.l_info[dyn->d_tag] = &local_dyn[ndyn++];
                break;
            case DT_HASH: {
                ElfW(Word)* h = (ElfW(Word)*)(D_PTR(dyn) + load_offset);
                vdso_map.l_nbuckets = h[0];
                vdso_map.l_buckets  = &h[2];
                vdso_map.l_chain    = &h[vdso_map.l_nbuckets + 2];
                break;
            }
            case DT_VERSYM:
            case DT_VERDEF:
                local_dyn[ndyn] = *dyn;
                local_dyn[ndyn].d_un.d_ptr += load_offset;
                vdso_map.l_info[VERSYMIDX(dyn->d_tag)] = &local_dyn[ndyn++];
                break;
        }

    const char* gettime = "__vdso_clock_gettime";
    uint_fast32_t fast_hash = elf_fast_hash(gettime);
    long int hash = elf_hash(gettime);
    ElfW(Sym)* sym = NULL;

    sym = do_lookup_map(NULL, gettime, fast_hash, hash, &vdso_map);
    if (sym)
        g_linux_state.vdso_clock_gettime = (void*)(load_offset + sym->st_value);
}
