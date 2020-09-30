/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * db_rtld.c
 *
 * This file contains utilities to load ELF binaries into the memory
 * and link them against each other.
 * The source code in this file is imported and modified from the GNU C
 * Library.
 */

#include <assert.h>

#include "api.h"
#include "elf-x86_64.h"
#include "elf/elf.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_rtld.h"
#include "pal_security.h"
#include "sgx_rtld.h"
#include "spinlock.h"
#include "sysdeps/generic/ldsodefs.h"

struct debug_map* _Atomic* g_debug_map = NULL;

/* Lock for modifying the debug_map linked list on our end. Even though the list can be read at any
 * time, we need to prevent concurrent modification. */
static spinlock_t g_debug_map_lock = INIT_SPINLOCK_UNLOCKED;

static struct debug_map* debug_map_alloc(const char* file_name, void* text_addr) {
    struct debug_map* map;

    if (!(map = malloc(sizeof(*map))))
        return NULL;

    if (!(map->file_name = strdup(file_name))) {
        free(map);
        return NULL;
    }

    map->text_addr = text_addr;
    map->section = NULL;
    map->next = NULL;
    return map;
}

static struct debug_section* debug_map_add_section(struct debug_map* map, const char* section_name,
                                                   void* addr) {
    struct debug_section* section;

    if (!(section = malloc(sizeof(*section))))
        return NULL;

    if (!(section->name = strdup(section_name))) {
        free(section);
        return NULL;
    }

    section->addr = addr;
    section->next = map->section;
    map->section = section;
    return section;
}

static void debug_map_free(struct debug_map* map) {
    struct debug_section* section = map->section;
    while (section) {
        struct debug_section* next = section->next;
        free(section->name);
        free(section);
        section = next;
    }
    free(map->file_name);
    free(map);
}

static void debug_map_add(struct debug_map* map) {
    assert(g_debug_map);

    spinlock_lock(&g_debug_map_lock);

    map->next = *g_debug_map;
    *g_debug_map = map;

    spinlock_unlock(&g_debug_map_lock);

    ocall_update_debugger();
}

static bool debug_map_del(const char* file_name) {
    assert(g_debug_map);

    spinlock_lock(&g_debug_map_lock);

    /* Note that this is insecure, as *g_debug_map is a value controlled outside of the enclave, so
     * the code could be forced to access and modify arbitrary memory.
     * However, g_debug_map is set only during debug builds.
     *
     * TODO: consider making the GDB integration conditional on a separate option such as
     * INSECURE__ENABLE_GDB.
     */
    struct debug_map* prev = NULL;
    struct debug_map* map = *g_debug_map;
    while (map) {
        if (strcmp(map->file_name, file_name) == 0)
            break;
        prev = map;
        map = map->next;
    }

    if (!map) {
        spinlock_unlock(&g_debug_map_lock);
        return false;
    }

    if (prev == NULL)
        *g_debug_map = map->next;
    else
        prev->next = map->next;

    spinlock_unlock(&g_debug_map_lock);

    debug_map_free(map);

    ocall_update_debugger();
    return true;
}

void _DkDebugAddMap(struct link_map* map) {
    const ElfW(Ehdr)* ehdr = (void*)map->l_map_start;
    int shdrsz = sizeof(ElfW(Shdr)) * ehdr->e_shnum;
    ElfW(Shdr)* shdr = NULL;
    ElfW(Phdr)* phdr = (void*)(map->l_map_start + ehdr->e_phoff);
    const ElfW(Phdr)* ph;

    int fd = ocall_open(map->l_name, O_RDONLY, 0);
    if (IS_ERR(fd))
        return;

    for (ph = phdr; ph < &phdr[ehdr->e_phnum]; ++ph)
        if (ph->p_type == PT_LOAD && ehdr->e_shoff >= ph->p_offset &&
            ehdr->e_shoff < ph->p_offset + ph->p_filesz) {
            shdr = (void*)map->l_addr + ph->p_vaddr + (ehdr->e_shoff - ph->p_offset);
            break;
        }

    if (!shdr) {
        shdr = __alloca(shdrsz);
        unsigned long s = ALLOC_ALIGN_DOWN(ehdr->e_shoff);
        unsigned long e = ALLOC_ALIGN_UP(ehdr->e_shoff + shdrsz);
        void* umem;
        ocall_mmap_untrusted(fd, s, e - s, PROT_READ, &umem);
        memcpy(shdr, umem + ehdr->e_shoff - s, shdrsz);
        ocall_munmap_untrusted(umem, e - s);
    }

    ElfW(Shdr)* shdrend = (void*)shdr + shdrsz;
    size_t shstroff = shdr[ehdr->e_shstrndx].sh_offset;
    size_t shstrsz = shdr[ehdr->e_shstrndx].sh_size;
    const char* shstrtab = NULL;

    for (ph = phdr; ph < &phdr[ehdr->e_phnum]; ++ph)
        if (ph->p_type == PT_LOAD && shstroff >= ph->p_offset &&
                shstroff < ph->p_offset + ph->p_filesz) {
            shstrtab = (void*)map->l_addr + ph->p_vaddr + (shstroff - ph->p_offset);
            break;
        }

    if (!shstrtab) {
        shstrtab = __alloca(shstrsz);
        unsigned long s = ALLOC_ALIGN_DOWN(shstroff);
        unsigned long e = ALLOC_ALIGN_UP(shstroff + shstrsz);
        void* umem;
        ocall_mmap_untrusted(fd, s, e - s, PROT_READ, &umem);
        memcpy((void*)shstrtab, umem + shstroff - s, shstrsz);
        ocall_munmap_untrusted(umem, e - s);
    }

    ocall_close(fd);

    ElfW(Addr) text_addr = 0;
    for (ElfW(Shdr)* s = shdr; s < shdrend; s++)
        if (!strcmp_static(shstrtab + s->sh_name, ".text")) {
            text_addr = map->l_addr + s->sh_addr;
            break;
        }

    if (!text_addr || !g_debug_map)
        return;

    struct debug_map* debug_map = debug_map_alloc(map->l_name, (void*)text_addr);
    if (!debug_map) {
        SGX_DBG(DBG_E, "_DkDebugAddMap: error allocating new map");
        return;
    }

    for (ElfW(Shdr)* s = shdr; s < shdrend; s++) {
        if (!s->sh_name || !s->sh_addr)
            continue;
        if (!strcmp_static(shstrtab + s->sh_name, ".text"))
            continue;
        if (s->sh_type == SHT_NULL)
            continue;
        if (strstartswith_static(shstrtab + s->sh_name, ".debug_"))
            continue;

        if (!debug_map_add_section(debug_map, shstrtab + s->sh_name,
                                   (void*)(map->l_addr + s->sh_addr))) {
            SGX_DBG(DBG_E, "_DkDebugAddMap: error allocating new section");
            debug_map_free(debug_map);
            return;
        }
    }

    debug_map_add(debug_map);
}

void _DkDebugDelMap(struct link_map* map) {
    debug_map_del(map->l_name);
}

extern void* g_section_text;
extern void* g_section_rodata;
extern void* g_section_dynamic;
extern void* g_section_data;
extern void* g_section_bss;

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

    if (!g_debug_map)
        return;

    struct debug_map* debug_map = debug_map_alloc(pal_map->l_name, &g_section_text);
    if (!debug_map) {
        SGX_DBG(DBG_E, "setup_pal_map: error allocating new map");
        return;
    }

    if (!debug_map_add_section(debug_map, ".rodata", &g_section_rodata))
        goto fail;

    if (!debug_map_add_section(debug_map, ".dynamic", &g_section_dynamic))
        goto fail;

    if (!debug_map_add_section(debug_map, ".data", &g_section_data))
        goto fail;

    if (!debug_map_add_section(debug_map, ".bss", &g_section_bss))
        goto fail;

    debug_map_add(debug_map);
    return;

fail:
    SGX_DBG(DBG_E, "setup_pal_map: error allocating new section");
    debug_map_free(debug_map);
}
