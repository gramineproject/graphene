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

#include "elf-x86_64.h"

void _DkDebugAddMap (struct link_map * map)
{
    const ElfW(Ehdr) * ehdr = (void *) map->l_map_start;
    int shdrsz = sizeof(ElfW(Shdr)) * ehdr->e_shnum;
    ElfW(Shdr) * shdr = NULL;
    ElfW(Phdr) * phdr = (void *) (map->l_map_start + ehdr->e_phoff);
    const ElfW(Phdr) * ph;

    int fd = ocall_open(map->l_name, O_RDONLY, 0);
    if (IS_ERR(fd))
        return;

    for (ph = phdr; ph < &phdr[ehdr->e_phnum]; ++ph)
        if (ph->p_type == PT_LOAD &&
            ehdr->e_shoff >= ph->p_offset &&
            ehdr->e_shoff < ph->p_offset + ph->p_filesz) {
            shdr = (void *) map->l_addr + ph->p_vaddr +
                (ehdr->e_shoff - ph->p_offset);
            break;
        }

    if (!shdr) {
        shdr = __alloca(shdrsz);
        unsigned long s = ALLOC_ALIGN_DOWN(ehdr->e_shoff);
        unsigned long e = ALLOC_ALIGN_UP(ehdr->e_shoff + shdrsz);
        void * umem;
        ocall_mmap_untrusted(fd, s, e - s, PROT_READ, &umem);
        memcpy(shdr, umem + ehdr->e_shoff - s, shdrsz);
        ocall_munmap_untrusted(umem, e - s);
    }

    ElfW(Shdr) * shdrend = (void *) shdr + shdrsz;
    size_t shstroff = shdr[ehdr->e_shstrndx].sh_offset;
    size_t shstrsz = shdr[ehdr->e_shstrndx].sh_size;
    const char * shstrtab = NULL;

    for (ph = phdr; ph < &phdr[ehdr->e_phnum]; ++ph)
        if (ph->p_type == PT_LOAD &&
            shstroff >= ph->p_offset &&
            shstroff < ph->p_offset + ph->p_filesz) {
            shstrtab = (void *) map->l_addr + ph->p_vaddr +
                (shstroff - ph->p_offset);
            break;
        }

    if (!shstrtab) {
        shstrtab = __alloca(shstrsz);
        unsigned long s = ALLOC_ALIGN_DOWN(shstroff);
        unsigned long e = ALLOC_ALIGN_UP(shstroff + shstrsz);
        void * umem;
        ocall_mmap_untrusted(fd, s, e - s, PROT_READ, &umem);
        memcpy((void *) shstrtab, umem + shstroff - s, shstrsz);
        ocall_munmap_untrusted(umem, e - s);
    }

    ocall_close(fd);

    ElfW(Addr) text_addr = 0;
    for (ElfW(Shdr) * s = shdr ; s < shdrend ; s++)
        if (!strcmp_static(shstrtab + s->sh_name, ".text")) {
            text_addr = map->l_addr + s->sh_addr;
            break;
        }

    if (!text_addr)
        return;

#define BUFFER_LENGTH 4096

    char buffer[BUFFER_LENGTH], * ptr = buffer;

    snprintf(ptr, BUFFER_LENGTH - (ptr - buffer),
             "add-symbol-file %s 0x%016lx -readnow", map->l_name, text_addr);
    ptr += strlen(ptr);

    for (ElfW(Shdr) * s = shdr ; s < shdrend ; s++) {
        if (!s->sh_name || !s->sh_addr)
            continue;
        if (!strcmp_static(shstrtab + s->sh_name, ".text"))
            continue;
        if (s->sh_type == SHT_NULL)
            continue;
        if (strstartswith_static(shstrtab + s->sh_name, ".debug_"))
            continue;

        snprintf(ptr, BUFFER_LENGTH - (ptr - buffer),
                 " -s %s 0x%016lx", shstrtab + s->sh_name,
                 map->l_addr + s->sh_addr);
        ptr += strlen(ptr);
    }

    ocall_load_debug(buffer);
}

void _DkDebugDelMap (struct link_map * map)
{
    char buffer[BUFFER_LENGTH];
    snprintf(buffer, BUFFER_LENGTH, "remove-symbol-file %s", map->l_name);
    ocall_load_debug(buffer);
}

void setup_elf_hash (struct link_map *map);

extern void * section_text, * section_rodata, * section_dynamic,
            * section_data, * section_bss;

void setup_pal_map (struct link_map * pal_map)
{
    const ElfW(Ehdr) * header = (void *) pal_map->l_addr;

    pal_map->l_real_ld = pal_map->l_ld = (void *) elf_machine_dynamic();
    pal_map->l_type = OBJECT_RTLD;
    pal_map->l_entry = header->e_entry;
    pal_map->l_phdr  = (void *) (pal_map->l_addr + header->e_phoff);
    pal_map->l_phnum = header->e_phnum;
    setup_elf_hash(pal_map);

    char buffer[BUFFER_LENGTH];
    snprintf(buffer, BUFFER_LENGTH,
             "add-symbol-file %s %p -readnow -s .rodata %p "
             "-s .dynamic %p -s .data %p -s .bss %p",
             pal_map->l_name,
             &section_text, &section_rodata, &section_dynamic,
             &section_data, &section_bss);

    ocall_load_debug(buffer);
    pal_map->l_prev = pal_map->l_next = NULL;
    loaded_maps = pal_map;
}
