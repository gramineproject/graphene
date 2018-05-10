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
 * pal_rtld.h
 */

#ifndef PAL_RTLD_H
#define PAL_RTLD_H

#include "pal_internal.h"
#include "pal_error.h"
#include "api.h"

#include <elf.h>

#define ElfW(type) Elf64_##type
#define ELFW(type) ELF64_##type

#ifndef DT_THISPROCNUM
# define DT_THISPROCNUM 0
#endif

#ifndef VERSYMIDX
# define VERSYMIDX(sym) (DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGIDX(sym))
#endif

#if __WORDSIZE == 32
# define FILEBUF_SIZE 512
#else
# define FILEBUF_SIZE 832
#endif

/* This is a simplified link_map structure */
DEFINE_LIST(link_map);
struct link_map {
    LIST_TYPE(link_map) list;
    enum link_map_type { MAP_RTLD, MAP_PRELOAD, MAP_EXEC } type;
    void *       base_addr;
    const char * binary_name;
    void *       map_start, * map_end;
    void *       entry;
    ElfW(Phdr) * phdr_addr;
    size_t       phdr_num;
    ElfW(Dyn) *  dyn_addr;
    size_t       dyn_num;
    ElfW(Sym) *  symbol_table;
    const char * string_table;
    ElfW(Rela) * rela_addr;
    size_t       rela_size;
    ElfW(Rela) * jmprel_addr;
    size_t       jmprel_size;
    ElfW(Word) * hash_buckets;
    ElfW(Word)   nbuckets;
    ElfW(Word) * hash_chain;
};

struct gdb_link_map {
    /* These first few members are part of the protocol with the debugger.
       This is the same format used in SVR4.  */
    void *       l_addr;        /* Base address shared object is loaded at. */
    const char * l_name;        /* Absolute file name object was found in.  */
    void *       l_ld;          /* Dynamic section of the shared object.    */
    struct gdb_link_map * l_next, * l_prev;   /* Chain of loaded objects.     */
};

/* Rendezvous structure used by the run-time dynamic linker to communicate
   details of shared object loading to the debugger.  If the executable's
   dynamic section has a DT_DEBUG element, the run-time linker sets that
   element's value to the address where this structure can be found.  */
struct r_debug {
    int r_version;           /* Version number for this protocol.  */

    struct gdb_link_map * r_map; /* Head of the chain of loaded objects.  */

    /* This is the address of a function internal to the run-time linker,
       that will always be called when the linker begins to map in a
       library or unmap it, and again when the mapping change is complete.
       The debugger can set a breakpoint at this address if it wants to
       notice shared object mapping changes.  */
    ElfW(Addr) r_brk;
    enum {
        /* This state value describes the mapping change taking place when
           the `r_brk' address is called.  */
        RT_CONSISTENT,  /* Mapping change is complete.  */
        RT_ADD,         /* Beginning to add a new object.  */
        RT_DELETE       /* Beginning to remove an object mapping.  */
    } r_state;

    ElfW(Addr) r_ldbase;    /* Base address the linker is loaded at.  */
};


extern struct link_map * rtld_map;
extern struct link_map * exec_map;

static inline int check_elf_object (PAL_HANDLE handle)
{
    unsigned char expected[] = { ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3 };
    unsigned char buf[EI_CLASS];
    ElfW(Ehdr) * ehdr = (ElfW(Ehdr) *) buf;

    int len = _DkStreamRead(handle, 0, EI_CLASS, buf, NULL, 0);
    if (len < 0)
        return -len;

    return memcmp(ehdr->e_ident, expected, EI_CLASS) ? -PAL_ERROR_INVAL : 0;
}

int load_link_map (struct link_map * map, PAL_HANDLE file,
                   void * loaded_addr, enum link_map_type type);
int load_elf_object (PAL_HANDLE file, void * loaded_addr,
                     enum link_map_type type);

static inline uint_fast32_t elf_fast_hash (const char *s)
{
  uint_fast32_t h = 5381;
  for (unsigned char c = *s; c != '\0'; c = *++s)
    h = h * 33 + c;
  return h & 0xffffffff;
}

unsigned long int elf_hash (const char *name_arg);

/* for GDB debugging */
void _DkDebugAttachBinary (const char * name, void * base_addr,
                           void * dynamic);

void _DkDebugAddMap (struct gdb_link_map * map);
void _DkDebugDelMap (struct gdb_link_map * map);

#endif /* PAL_RTLD_H */
