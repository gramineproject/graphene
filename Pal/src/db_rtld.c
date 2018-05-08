/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

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
#include "pal.h"
#include "pal_internal.h"
#include "pal_debug.h"
#include "pal_error.h"
#include "pal_rtld.h"
#include "api.h"

DEFINE_LISTP(link_map);
LISTP_TYPE(link_map) link_map_list = LISTP_INIT;

#ifdef assert
/* This function can be used as a breakpoint to debug assertion */
void __attribute_noinline __assert (void)
{
    BREAK();
}
#endif

static uint32_t sysv_hash (const char *str)
{
    const unsigned char * s = (void *) str;
    uint_fast32_t h = 0;
    while (*s) {
        h = 16 * h + *s++;
        h ^= (h >> 24) & 0xf0;
    }
    return h & 0xfffffff;
}

static void * resolve_symbol (struct link_map * map, ElfW(Sym) * undef_sym)
{
    const char * name = map->string_table + undef_sym->st_name;
    int namelen = strlen(name);
    uint32_t hash = sysv_hash(name);

    struct link_map * m;
    listp_for_each_entry(m, &link_map_list, list) {
        /* Only support SYSV hashing */
        if (!m->hash_buckets)
            continue;

        for (ElfW(Word) idx = m->hash_buckets[hash % m->nbuckets] ;
             idx != STN_UNDEF ;
             idx = m->hash_chain[idx]) {
            ElfW(Sym) * sym = &m->symbol_table[idx];
            if (!memcmp(m->string_table + sym->st_name,
                        name, namelen + 1))
                return m->base_addr + sym->st_value;
        }
    }

    return NULL;
}

int load_link_map (struct link_map * map, PAL_HANDLE file,
                   void * loaded_addr, enum link_map_type type)
{
    int64_t ret;

    char filebuf[FILEBUF_SIZE];
    if (loaded_addr) {
        memcpy(filebuf, loaded_addr, FILEBUF_SIZE);
    } else {
        ret = _DkStreamRead(file, 0, FILEBUF_SIZE, &filebuf, NULL, 0);
        if (ret < 0)
            return ret;
    }

    const ElfW(Ehdr) * ehdr = (void *) filebuf;
    const ElfW(Phdr) * phdr = (void *) filebuf + ehdr->e_phoff;
    const ElfW(Phdr) * ph;
    void * map_start = (void *) -1, * map_end = NULL;

    memset(map, 0, sizeof(*map));
    INIT_LIST_HEAD(map, list);
    map->type = type;

    for (ph = phdr ; ph < &phdr[ehdr->e_phnum] ; ph++)
        switch (ph->p_type) {
            case PT_DYNAMIC:
                map->dyn_addr = (ElfW(Dyn) *) ph->p_vaddr;
                map->dyn_num  = ph->p_memsz / sizeof (ElfW(Dyn));
                break;
            case PT_LOAD: {
                void * start = (void *) ALLOC_ALIGNDOWN(ph->p_vaddr);
                void * end = (void *) ALLOC_ALIGNUP(ph->p_vaddr + ph->p_memsz);
                if (start < map_start)
                    map_start = start;
                if (end > map_end)
                    map_end = end;
                break;
            }
        }

    if (map_start >= map_end)
        return -PAL_ERROR_INVAL;

    void * map_base = NULL;

    if (loaded_addr) {
        map_base = loaded_addr - (uintptr_t) map_start;
    } else {
        void * map_addr = (ehdr->e_type == ET_DYN) ? NULL : map_start;
        ret = _DkStreamMap(file, &map_addr, PAL_PROT_NONE, 0, map_end - map_start);
        if (ret < 0)
            return -PAL_ERROR_NOMEM;

        if (ehdr->e_type == ET_DYN)
        map_base = (void *) (map_addr - map_start);

        for (ph = phdr ; ph < &phdr[ehdr->e_phnum] ; ph++) {
            if (ph->p_type != PT_LOAD)
                continue;

            void * start = (void *) ALLOC_ALIGNDOWN(ph->p_vaddr);
            void * end = (void *) ALLOC_ALIGNUP(ph->p_vaddr + ph->p_memsz);
            void * file_end = (void *) ALLOC_ALIGNUP(ph->p_vaddr + ph->p_filesz);
            uint64_t file_off = ALLOC_ALIGNDOWN(ph->p_offset);
            map_addr = map_base + (uintptr_t) start;

            int prot = 0;
            if (ph->p_flags & PF_R)
                prot |= PAL_PROT_READ;
            if (ph->p_flags & PF_W)
                prot |= PAL_PROT_WRITE|PAL_PROT_WRITECOPY;
            if (ph->p_flags & PF_X)
                prot |= PAL_PROT_EXEC;

            ret = _DkStreamMap(file, &map_addr, prot, file_off,
                               file_end - start);
            if (ret < 0)
                return ret;

            if (end > file_end) {
                map_addr = map_base + (uintptr_t) file_end;
                ret = _DkVirtualMemoryAlloc(&map_addr, end - file_end,
                                            0, prot);
                if (ret < 0)
                    return ret;
            }
        }
    }

    map->base_addr = map_base;
    map->dyn_addr  = map_base + (uintptr_t) map->dyn_addr;
    map->map_start = map_base + (uintptr_t) map_start;
    map->map_end   = map_base + (uintptr_t) map_end;
    map->entry     = map_base + (uintptr_t) ehdr->e_entry;
    map->phdr_addr = map->map_start + ehdr->e_phoff;
    map->phdr_num  = ehdr->e_phnum;

    ElfW(Dyn) * dyn = map->dyn_addr;
    for (; dyn < map->dyn_addr + map->dyn_num ; ++dyn)
        switch(dyn->d_tag) {
            case DT_SYMTAB:
                map->symbol_table =
                    (ElfW(Sym) *) (map->base_addr + dyn->d_un.d_ptr);
                break;
            case DT_STRTAB:
                map->string_table =
                    (const char *) (map->base_addr + dyn->d_un.d_ptr);
                break;
            case DT_HASH: {
                /*
                 * Structure of DT_HASH:
                 *  [      nbuckets      ]
                 *  [       nchain       ]
                 *  [     buckets[0]     ]
                 *  [        ...         ]
                 *  [ buckets[nbucket-1] ]
                 *  [      chain[0]      ]
                 *  [        ...         ]
                 *  [  chain[nchain-1]   ]
                 */
                ElfW(Word) * hash =
                        (ElfW(Word) *) (map->base_addr + dyn->d_un.d_ptr);
                map->nbuckets = *hash++;
                hash++;
                map->hash_buckets = hash;
                hash += map->nbuckets;
                map->hash_chain = hash;
            }
            case DT_RELA:
                map->rela_addr =
                    (ElfW(Rela) *) (map->base_addr + dyn->d_un.d_ptr);
                break;
            case DT_RELASZ:
                map->rela_size = dyn->d_un.d_val;
                break;
            case DT_JMPREL:
                map->jmprel_addr =
                    (ElfW(Rela) *) (map->base_addr + dyn->d_un.d_ptr);
                break;
            case DT_PLTRELSZ:
                map->jmprel_size = dyn->d_un.d_val;
                break;
            case DT_REL:
            case DT_RELCOUNT:
                init_fail(-PAL_ERROR_INVAL, "PAL only supports RELA binaries");
                break;
        }

    if (!map->hash_buckets) {
        if (type == MAP_RTLD || type == MAP_PRELOAD)
            init_fail(-PAL_ERROR_INVAL, "Either PAL or preloaded libraries "
                      "must use System V hash functions");
    }

    ElfW(Rela) * reloc_ranges[2][2] = {
            { map->rela_addr,   ((void *) map->rela_addr   + map->rela_size) },
            { map->jmprel_addr, ((void *) map->jmprel_addr + map->jmprel_size) },
        };

    for (int i = 0 ; i < 2 ; i++) {
        ElfW(Rela) * rel = reloc_ranges[i][0];
        if (!rel)
            continue;

        for (; rel < reloc_ranges[i][1] ; rel++) {
            unsigned long int r_type = ELFW(R_TYPE) (rel->r_info);
            void ** reloc_addr = map_base + rel->r_offset;
            ElfW(Sym) * sym = &map->symbol_table[ELFW(R_SYM) (rel->r_info)];
            switch(r_type) {
                case R_X86_64_GLOB_DAT:
                case R_X86_64_JUMP_SLOT:
                    if (!sym->st_value) {
                        /* Only resolve undefined symbols */
                        void * resolved_addr = resolve_symbol(map, sym);
                        if (resolved_addr)
                            *reloc_addr = resolved_addr + rel->r_addend;
                        else
                            init_fail(-PAL_ERROR_INVAL, "Unknown symbol: %s",
                                      map->string_table + sym->st_name);
                        break;
                    }
                case R_X86_64_64:
                case R_X86_64_32:
                    *reloc_addr = map_base + sym->st_value + rel->r_addend;
                    break;
                case R_X86_64_RELATIVE:
                    *reloc_addr = map_base + rel->r_addend;
                    break;
                default:
                    init_fail(-PAL_ERROR_INVAL, "Unknown relocation type");
                    break;
            }
        }
    }

    return 0;
}

int load_elf_object (PAL_HANDLE file, void * load_addr,
                     enum link_map_type type)
{
    struct link_map * map = malloc(sizeof(struct link_map));
    if (!map)
        return -PAL_ERROR_NOMEM;

    int ret = load_link_map(map, file, load_addr, type);
    if (ret < 0) {
        free(map);
        return ret;
    }

    listp_add_tail(map, &link_map_list, list);
    return 0;
}

void DkDebugAttachBinary (PAL_STR uri, PAL_PTR start_addr)
{
#ifdef DEBUG
    if (!strpartcmp_static(uri, "file:"))
        return;

    struct link_map * map = malloc(sizeof(struct link_map));
    if (!map)
        return;

    const char * name = uri + static_strlen("file:");
    map->binary_name = malloc_copy(name, strlen(name) + 1);

    /* This is the ELF header.  We read it in `open_verify'.  */
    const ElfW(Ehdr) * header = (ElfW(Ehdr) *) start_addr;

    map->entry = (void *) header->e_entry;
    map->phdr_num = header->e_phnum;
    map->map_start = (void *) start_addr;

    ElfW(Phdr) * phdr = (void *) ((char *) start_addr + header->e_phoff);
    const ElfW(Phdr) * ph;
    ElfW(Addr) map_start = 0, map_end = 0;

    for (ph = phdr; ph < &phdr[map->phdr_num]; ++ph)
        if (ph->p_type == PT_PHDR) {
            if (!map_start || ph->p_vaddr < map_start)
                map_start = ph->p_vaddr;
            if (!map_end || ph->p_vaddr + ph->p_memsz > map_end)
                map_end = ph->p_vaddr + ph->p_memsz;
        }

    map->base_addr = map->map_start - map_start;
    map->map_end = map->base_addr + map_end;

    for (ph = phdr; ph < &phdr[map->phdr_num]; ++ph)
        switch (ph->p_type) {
            case PT_PHDR:
                map->phdr_addr = (ElfW(Phdr) *) ((char *) map->base_addr + ph->p_vaddr);
                break;
        }

    _DkDebugAddMap(map);
#endif
}

void DkDebugDetachBinary (PAL_PTR start_addr)
{
#if 0
    for (struct link_map * l = loaded_maps; l; l = map->l_next)
        if (map->l_map_start == (ElfW(Addr)) start_addr) {
            _DkDebugDelMap(l);

            if (map->l_type == OBJECT_EXTERNAL)
                free_elf_object(l);
            break;
        }
#endif
}

#ifndef CALL_ENTRY
#ifdef __x86_64__
void * stack_before_call __attribute_unused = NULL;

#define CALL_ENTRY(map, cookies)                                        \
    ({  long ret;                                                       \
        asm volatile("movq %%rsp, stack_before_call(%%rip)\r\n"         \
                     "leaq 1f(%%rip), %%rdx\r\n"                        \
                     "movq %2, %%rsp\r\n"                               \
                     "jmp *%1\r\n"                                      \
                     "1: movq stack_before_call(%%rip), %%rsp\r\n"      \
                                                                        \
                     : "=a"(ret) : "a"(map->entry), "b"(cookies)        \
                     : "rcx", "rdx", "rdi", "rsi", "r8", "r9",          \
                       "r10", "r11", "memory");                         \
        ret; })
#else
# error "unsupported architecture"
#endif
#endif /* !CALL_ENTRY */

void start_execution (const char * first_argument, const char ** arguments,
                      const char ** environs)
{
#if PROFILING == 1
    unsigned long before_tail = _DkSystemTimeQuery();
#endif

    struct link_map * exec_map =
            listp_last_entry(&link_map_list, struct link_map, list);

    if (exec_map->type != MAP_EXEC)
        exec_map = NULL;

    /* First we will try to run all the preloaded libraries which come with
       entry points */
    if (exec_map) {
        __pal_control.executable_range.start = (PAL_PTR) exec_map->map_start;
        __pal_control.executable_range.end   = (PAL_PTR) exec_map->map_end;
    }

    int narguments = 0;
    if (first_argument)
        narguments++;
    for (const char ** a = arguments; *a ; a++, narguments++);

    /* Let's count the number of cookies, first we will have argc & argv */
    int ncookies = narguments + 3; /* 1 for argc, argc + 2 for argv */

    /* Then we count envp */
    for (const char ** e = environs; *e; e++)
        ncookies++;

    ncookies++; /* for NULL-end */

    int cookiesz = sizeof(unsigned long int) * ncookies
                      + sizeof(ElfW(auxv_t)) * 6
                      + sizeof(void *) * 4 + 16;

    unsigned long int * cookies = __alloca(cookiesz);
    int cnt = 0;

    /* Let's copy the cookies */
    cookies[cnt++] = (unsigned long int) narguments;
    if (first_argument)
        cookies[cnt++] = (unsigned long int) first_argument;

    for (int i = 0 ; arguments[i] ; i++)
        cookies[cnt++] = (unsigned long int) arguments[i];
    cookies[cnt++] = 0;
    for (int i = 0 ; environs[i]; i++)
        cookies[cnt++] = (unsigned long int) environs[i];
    cookies[cnt++] = 0;

    ElfW(auxv_t) * auxv = (ElfW(auxv_t) *) &cookies[cnt];
    auxv[0].a_type = AT_PHDR;
    auxv[0].a_un.a_val = exec_map ? (uintptr_t) exec_map->phdr_addr : 0;
    auxv[1].a_type = AT_PHNUM;
    auxv[1].a_un.a_val = exec_map ? exec_map->phdr_num : 0;
    auxv[2].a_type = AT_PAGESZ;
    auxv[2].a_un.a_val = __pal_control.pagesize;
    auxv[3].a_type = AT_ENTRY;
    auxv[3].a_un.a_val = exec_map ? (uintptr_t) exec_map->entry : 0;
    auxv[4].a_type = AT_BASE;
    auxv[4].a_un.a_val = exec_map ? (uintptr_t) exec_map->base_addr : 0;
    auxv[5].a_type = AT_NULL;

    *(void **) &auxv[6] = NULL;

#if PROFILING == 1
    __pal_control.startup_time = _DkSystemTimeQuery() - pal_state.start_time;
    __pal_control.tail_startup_time =
            pal_state.tail_startup_time += _DkSystemTimeQuery() - before_tail;
#endif

    struct link_map * map;
    listp_for_each_entry(map, &link_map_list, list) {
        if (map->type == MAP_RTLD || !map->entry)
            continue;

        CALL_ENTRY(map, cookies);
    }

    _DkThreadExit();
}
