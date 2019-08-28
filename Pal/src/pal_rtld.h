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

#include <sysdeps/generic/ldsodefs.h>
#include <elf/elf.h>

#ifndef DT_THISPROCNUM
# define DT_THISPROCNUM 0
#endif

typedef ElfW(Word) Elf_Symndx;

/* Structure describing a loaded shared object.  The `l_next' and `l_prev'
   members form a chain of all the shared objects loaded at startup.

   These data structures exist in space used by the run-time dynamic linker;
   modifying them may have disastrous results.

   This data structure might change in future, if necessary.  User-level
   programs must avoid defining objects of this type.  */

/* This is a simplified link_map structure */

struct link_map {
    /* These first few members are part of the protocol with the debugger.
       This is the same format used in SVR4.  */

    ElfW(Addr)   l_addr;        /* Base address shared object is loaded at. */
    const char * l_name;        /* Absolute file name object was found in.  */
    ElfW(Dyn) *  l_real_ld;     /* Dynamic section of the shared object.    */
    struct link_map * l_next, * l_prev;     /* Chain of loaded objects.     */

    /* All following members are internal to the dynamic linker.
       They may change without notice.  */
    enum object_type l_type;

    ElfW(Dyn) * l_ld;
    ElfW(Dyn) * l_info[DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM
                       + DT_EXTRANUM + DT_VALNUM + DT_ADDRNUM];
    const ElfW(Phdr) * l_phdr;  /* Pointer to program header table in core.  */
    ElfW(Addr) l_entry;     /* Entry point location.  */
    ElfW(Half) l_phnum;     /* Number of program header entries.  */
    ElfW(Half) l_ldnum;     /* Number of dynamic segment entries.  */

    /* Start and finish of memory map for this object.  l_map_start
       need not be the same as l_addr.  */
    ElfW(Addr) l_map_start, l_map_end;

    /* Information used to change permission after the relocations are
       done.   */
    ElfW(Addr) l_relro_addr;
    int l_relro_size;

    Elf_Symndx l_nbuckets;

    /* For DT_HASH */
    const Elf_Symndx *l_buckets;
    const Elf_Symndx *l_chain;

    /* For DT_GNU_HASH */
    Elf32_Word l_gnu_bitmask_idxbits;
    Elf32_Word l_gnu_shift;
    const ElfW(Addr) * l_gnu_bitmask;
    const Elf32_Word * l_gnu_buckets;
    const Elf32_Word * l_gnu_chain_zero;

#if CACHE_LOADED_BINARIES == 1
#define NRELOCS 64
    ElfW(Addr) * relocs[NRELOCS];
    int nrelocs;
#endif
};

struct link_gdb_map {
    /* These first few members are part of the protocol with the debugger.
       This is the same format used in SVR4.  */

    ElfW(Addr) l_addr;          /* Base address shared object is loaded at. */
    const char * l_name;        /* Absolute file name object was found in.  */
    ElfW(Dyn) * l_ld;           /* Dynamic section of the shared object.    */
    struct link_map * l_next, * l_prev;     /* Chain of loaded objects.     */
};

extern struct link_map * loaded_maps;
extern struct link_map * rtld_map;
extern struct link_map * exec_map;

/* Some systems link their relocatable objects for another base address
   than 0.  We want to know the base address for these such that we can
   subtract this address from the segment addresses during mapping.
   This results in a more efficient address space usage.  Defaults to
   zero for almost all systems.  */
#ifndef MAP_BASE_ADDR
# define MAP_BASE_ADDR(l) 0
#endif

/* Handle situations where we have a preferred location in memory for
   the shared objects.  */
#ifdef ELF_PREFERRED_ADDRESS_DATA
ELF_PREFERRED_ADDRESS_DATA;
#endif

#ifndef ELF_PREFERRED_ADDRESS
# define ELF_PREFERRED_ADDRESS(loader, maplength, mapstartpref) (mapstartpref)
#endif

#ifndef ELF_FIXED_ADDRESS
# define ELF_FIXED_ADDRESS(loader, mapstart) ((void)0)
#endif

#ifndef VERSYMIDX
# define VERSYMIDX(sym) (DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGIDX(sym))
#endif

#ifndef VALIDX
# define VALIDX(tag) (DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM \
                      + DT_EXTRANUM + DT_VALTAGIDX(tag))
#endif

#include <host_endian.h>
#if __BYTE_ORDER == __BIG_ENDIAN
# define byteorder ELFDATA2MSB
#elif __BYTE_ORDER == __LITTLE_ENDIAN
# define byteorder ELFDATA2LSB
#else
# error "Unknown __BYTE_ORDER " __BYTE_ORDER
# define byteorder ELFDATANONE
#endif

#if __WORDSIZE == 32
# define FILEBUF_SIZE 512
#else
# define FILEBUF_SIZE 832
#endif

struct link_map *
new_elf_object (const char * realname, enum object_type type);
void free_elf_object (struct link_map * map);

static inline uint_fast32_t elf_fast_hash (const char *s)
{
  uint_fast32_t h = 5381;
  for (unsigned char c = *s; c != '\0'; c = *++s)
    h = h * 33 + c;
  return h & 0xffffffff;
}

unsigned long int elf_hash (const char *name_arg);

ElfW(Sym) *
do_lookup_map (ElfW(Sym) * ref, const char * undef_name,
               const uint_fast32_t hash, unsigned long int elf_hash,
               const struct link_map * map);

/* for GDB debugging */
void _DkDebugAddMap (struct link_map * map);
void _DkDebugDelMap (struct link_map * map);

noreturn void start_execution(const char** arguments, const char** environs);

#endif /* PAL_RTLD_H */
