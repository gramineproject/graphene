/* Run-time dynamic linker data structures for loaded ELF shared objects.
   Copyright (C) 1995-2009, 2010 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#ifndef _LDSODEFS_H
#define _LDSODEFS_H 1

#include <sys/mman.h>

#include "elf/elf.h"
#include "stdbool.h"
#include "stddef.h"

/* We use this macro to refer to ELF types independent of the native wordsize.
   `ElfW(TYPE)' is used in place of `Elf32_TYPE' or `Elf64_TYPE'.  */
#define ElfW(type)       _ElfW(Elf, __ELF_NATIVE_CLASS, type)
#define _ElfW(e, w, t)   _ElfW_1(e, w, _##t)
#define _ElfW_1(e, w, t) e##w##t

/* This symbol refers to the "dynamic structure" in the `.dynamic' section
   of whatever module refers to `_DYNAMIC'.  So, to find its own
   `struct r_debug', a program could do:
       for (dyn = _DYNAMIC; dyn->d_tag != DT_NULL; ++dyn)
           if (dyn->d_tag == DT_DEBUG)
               r_debug = (struct r_debug *) dyn->d_un.d_ptr;
*/
extern ElfW(Dyn) _DYNAMIC[];

/* We use this macro to refer to ELF types independent of the native wordsize.
   `ElfW(TYPE)' is used in place of `Elf32_TYPE' or `Elf64_TYPE'.  */
#define ELFW(type) _ElfW(ELF, __ELF_NATIVE_CLASS, type)

/* We don't like the link_map form ld.so. This macro will be redefined */
#define D_PTR(sym) (sym)->d_un.d_ptr

#if 0 /* Remove this part for now */
/* All references to the value of l_info[DT_PLTGOT],
  l_info[DT_STRTAB], l_info[DT_SYMTAB], l_info[DT_RELA],
  l_info[DT_REL], l_info[DT_JMPREL], and l_info[VERSYMIDX (DT_VERSYM)]
  have to be accessed via the D_PTR macro.  The macro is needed since for
  most architectures the entry is already relocated - but for some not
  and we need to relocate at access time.  */
#ifdef DL_RO_DYN_SECTION
#define D_PTR(map, i) ((map)->i->d_un.d_ptr + (map)->l_addr)
#else
#define D_PTR(map, i) (map)->i->d_un.d_ptr
#endif

/* On some architectures a pointer to a function is not just a pointer
   to the actual code of the function but rather an architecture
   specific descriptor. */
#ifndef ELF_FUNCTION_PTR_IS_SPECIAL
#define DL_SYMBOL_ADDRESS(map, ref)    (void*)(LOOKUP_VALUE_ADDRESS(map) + ref->st_value)
#define DL_LOOKUP_ADDRESS(addr)        ((ElfW(Addr))(addr))
#define DL_DT_INIT_ADDRESS(map, start) (start)
#define DL_DT_FINI_ADDRESS(map, start) (start)
#endif
#endif

/* On some architectures dladdr can't use st_size of all symbols this way.  */
#define DL_ADDR_SYM_MATCH(L, SYM, MATCHSYM, ADDR)                 \
    ((ADDR) >= (L)->l_addr + (SYM)->st_value &&                   \
     ((((SYM)->st_shndx == SHN_UNDEF || (SYM)->st_size == 0) &&   \
       (ADDR) == (L)->l_addr + (SYM)->st_value) ||                \
      (ADDR) < (L)->l_addr + (SYM)->st_value + (SYM)->st_size) && \
     ((MATCHSYM) == NULL || (MATCHSYM)->st_value < (SYM)->st_value))

/* Unmap a loaded object, called by _dl_close (). */
#ifndef DL_UNMAP_IS_SPECIAL
#define DL_UNMAP(map) __munmap((void*)(map)->l_map_start, (map)->l_map_end - (map)->l_map_start)
#endif

/* By default we do not need special support to initialize DSOs loaded
   by statically linked binaries.  */
#ifndef DL_STATIC_INIT
#define DL_STATIC_INIT(map)
#endif

/* Reloc type classes as returned by elf_machine_type_class().
   ELF_RTYPE_CLASS_PLT means this reloc should not be satisfied by
   some PLT symbol, ELF_RTYPE_CLASS_COPY means this reloc should not be
   satisfied by any symbol in the executable.  Some architectures do
   not support copy relocations.  In this case we define the macro to
   zero so that the code for handling them gets automatically optimized
   out.  */
#define ELF_RTYPE_CLASS_PLT 1
#ifndef DL_NO_COPY_RELOCS
#define ELF_RTYPE_CLASS_COPY 2
#else
#define ELF_RTYPE_CLASS_COPY 0
#endif

/* ELF uses the PF_x macros to specify the segment permissions, mmap
   uses PROT_xxx.  In most cases the three macros have the values 1, 2,
   and 3 but not in a matching order.  The following macros allows
   converting from the PF_x values to PROT_xxx values.  */
#define PF_TO_PROT                                                                        \
    ((PROT_READ << (PF_R * 4)) | (PROT_WRITE << (PF_W * 4)) | (PROT_EXEC << (PF_X * 4)) | \
     ((PROT_READ | PROT_WRITE) << ((PF_R | PF_W) * 4)) |                                  \
     ((PROT_READ | PROT_EXEC) << ((PF_R | PF_X) * 4)) |                                   \
     ((PROT_WRITE | PROT_EXEC) << (PF_W | PF_X) * 4) |                                    \
     ((PROT_READ | PROT_WRITE | PROT_EXEC) << ((PF_R | PF_W | PF_X) * 4)))

/* For the version handling we need an array with only names and their
   hash values.  */
struct r_found_version {
    const char* name;
    ElfW(Word) hash;

    int hidden;
    const char* filename;
};

/* We want to cache information about the searches for shared objects.  */

enum r_dir_status { unknown, nonexisting, existing };

struct r_search_path_elem {
    /* This link is only used in the `all_dirs' member of `r_search_path'.  */
    struct r_search_path_elem* next;

    /* Strings saying where the definition came from.  */
    const char* what;
    const char* where;

    /* Basename for this search path element.  The string must end with
       a slash character.  */
    const char* dirname;
    size_t dirnamelen;

    enum r_dir_status status[0];
};

struct r_strlenpair {
    const char* str;
    size_t len;
};

/* A data structure for a simple single linked list of strings.  */
struct libname_list {
    const char* name;          /* Name requested (before search).  */
    struct libname_list* next; /* Link to next name for this object.  */
    int dont_free;             /* Flag whether this element should be freed
                                  if the object is not entirely unloaded.  */
};

/* Bit masks for the objects which valid callers can come from to
   functions with restricted interface.  */
enum allowmask { allow_libc = 1, allow_libdl = 2, allow_libpthread = 4, allow_ldso = 8 };

/* search loaded objects' symbol tables for a definition of the symbol
   referred to by undef.  *sym is the symbol table entry containing the
   reference; it is replaced with the defining symbol, and the base load
   address of the defining object is returned.  symbol_scope is a
   null-terminated list of object scopes to search; each object's
   l_searchlist (i.e. the segment of the dependency tree starting at that
   object) is searched in turn.  reference_name should name the object
   containing the reference; it is used in error messages.
   type_class describes the type of symbol we are looking for.  */
enum {
    /* if necessary add dependency between user and provider object.  */
    dl_lookup_add_dependency = 1,
    /* return most recent version instead of default version for
       unversioned lookup.  */
    dl_lookup_return_newest = 2,
    /* set if dl_lookup* called with gscope lock held.  */
    dl_lookup_gscope_lock = 4,
};

#define DL_LOOKUP_ADD_DEPENDENCY dl_lookup_add_dependency
#define DL_LOOKUP_RETURN_NEWEST  dl_lookup_return_newest
#define DL_LOOKUP_GSCOPE_LOCK    dl_lookup_gscope_lock

#endif /* ldsodefs.h */
