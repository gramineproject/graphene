/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains host-specific code related to linking and reporting ELFs to debugger.
 *
 * Overview of ELF files used in this host:
 * - pal-sgx and libraries it uses (outside enclave) - handled by ld.so and reported by it (through
 *   _r_debug mechanism)
 * - libpal.so (in enclave) - reported in sgx_main.c before enclave start
 * - LibOS, application, libc... (in enclave) - reported through DkDebugMap*
 *
 * In addition, we report executable memory mappings to the profiling subsystem.
 */

#include "api.h"
#include "elf-x86_64.h"
#include "elf/elf.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_linux.h"
#include "pal_rtld.h"

void _DkDebugMapAdd(const char* name, void* addr) {
    ocall_debug_map_add(name, addr);

    const ElfW(Ehdr)* ehdr = addr;
    ElfW(Phdr)* phdr = (void*)(addr + ehdr->e_phoff);
    const ElfW(Phdr)* ph;
    for (ph = phdr; ph < &phdr[ehdr->e_phnum]; ++ph)
        if (ph->p_type == PT_LOAD && ph->p_flags & PF_X) {
            uint64_t mapstart = ALLOC_ALIGN_DOWN(ph->p_vaddr);
            uint64_t mapend = ALLOC_ALIGN_UP(ph->p_vaddr + ph->p_filesz);
            uint64_t offset = ALLOC_ALIGN_DOWN(ph->p_offset);
            ocall_report_mmap(name, (uint64_t)addr + mapstart, mapend - mapstart, offset);
        }
}

void _DkDebugMapRemove(void* addr) {
    ocall_debug_map_remove(addr);
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
