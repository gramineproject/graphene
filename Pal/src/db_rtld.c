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
#include "pal.h"
#include "pal_internal.h"
#include "pal_debug.h"
#include "pal_error.h"
#include "pal_rtld.h"
#include "api.h"

#include <sysdeps/generic/ldsodefs.h>
#include <elf/elf.h>
#include <bits/dlfcn.h>

struct link_map * loaded_libraries = NULL;
struct link_map * rtld_map = NULL;
struct link_map * exec_map = NULL;
bool run_preload = false;

struct link_map * lookup_symbol (const char *undef_name, ElfW(Sym) **ref);

#ifdef assert
/* This function can be used as a breakpoint to debug assertion */
void __attribute__((noinline)) __assert (void)
{
    BREAK();
}
#endif

/* This structure communicates dl state to the debugger.  The debugger
   normally finds it via the DT_DEBUG entry in the dynamic section, but in
   a statically-linked program there is no dynamic section for the debugger
   to examine and it looks for this particular symbol name.  */
struct r_debug pal_r_debug =
        { 1, NULL, (ElfW(Addr)) &pal_dl_debug_state, RT_CONSISTENT, 0 };

extern __typeof(pal_r_debug) _r_debug
    __attribute ((alias ("pal_r_debug")));

    /* This function exists solely to have a breakpoint set on it by the
   debugger.  The debugger is supposed to find this function's address by
   examining the r_brk member of struct r_debug, but GDB 4.15 in fact looks
   for this particular symbol name in the PT_INTERP file.  */

/* The special symbol name is set as breakpoint in gdb */
void __attribute__((noinline)) pal_dl_debug_state (void)
{
}

extern __typeof(pal_dl_debug_state) _dl_debug_state
    __attribute ((alias ("pal_dl_debug_state")));

void __attribute__((noinline)) _dl_debug_state_trigger (void)
{
    struct link_map *l = pal_r_debug.r_map;
    for ( ; l ; l = l->l_next)
        if (!memcmp(l->l_name, "file:", 5))
            l->l_name += 5;

    pal_dl_debug_state();
}

/* This macro is used as a callback from the ELF_DYNAMIC_RELOCATE code.  */
static ElfW(Addr) resolve_map (const char **strtab, ElfW(Sym) ** ref)
{
    if (ELFW(ST_BIND) ((*ref)->st_info) != STB_LOCAL) {
        struct link_map * l = lookup_symbol((*strtab) + (*ref)->st_name, ref);
        if (l) {
            *strtab = (const void *) D_PTR (l->l_info[DT_STRTAB]);
            return l->l_addr;
        }
    }
    return 0;
}

#define RESOLVE_MAP(strtab, ref) resolve_map(strtab, ref)

#include "dynamic_link.h"
#include "dl-machine-x86_64.h"

/* Allocate a `struct link_map' for a new object being loaded,
   and enter it into the _dl_loaded list.  */
struct link_map *
new_elf_object (const char * realname, enum object_type type)
{
    struct link_map *new;

    new = (struct link_map *) malloc(sizeof (struct link_map));
    if (new == NULL)
        return NULL;

    /* We apparently expect this to be zeroed. */
    memset(new, 0, sizeof(struct link_map));

    new->l_name = realname ?
                  remalloc(realname, strlen(realname) + 1) :
                  NULL;
    new->l_type = type;
    return new;
}

/* Cache the location of MAP's hash table.  */
void setup_elf_hash (struct link_map *map)
{
    Elf_Symndx * hash;

    if (__builtin_expect (map->l_info[DT_ADDRTAGIDX (DT_GNU_HASH) + DT_NUM
                    + DT_THISPROCNUM + DT_VERSIONTAGNUM
                    + DT_EXTRANUM + DT_VALNUM] != NULL, 1)) {
        Elf32_Word *hash32
            = (void *) D_PTR (map->l_info[DT_ADDRTAGIDX (DT_GNU_HASH) + DT_NUM
                        + DT_THISPROCNUM + DT_VERSIONTAGNUM
                        + DT_EXTRANUM + DT_VALNUM]);

        map->l_nbuckets = *hash32++;

        Elf32_Word symbias = *hash32++;
        Elf32_Word bitmask_nwords = *hash32++;

        /* Must be a power of two.  */
        assert ((bitmask_nwords & (bitmask_nwords - 1)) == 0);
        map->l_gnu_bitmask_idxbits = bitmask_nwords - 1;
        map->l_gnu_shift = *hash32++;

        map->l_gnu_bitmask = (ElfW(Addr) *) hash32;
        hash32 += __ELF_NATIVE_CLASS / 32 * bitmask_nwords;

        map->l_gnu_buckets = hash32;
        hash32 += map->l_nbuckets;
        map->l_gnu_chain_zero = hash32 - symbias;

        return;
    }

    if (!map->l_info[DT_HASH])
        return;

    hash = (void *) D_PTR (map->l_info[DT_HASH]);

    /* Structure of DT_HASH:
         The bucket array forms the hast table itself. The entries in the
         chain array parallel the symbol table.
         [        nbucket        ]
         [        nchain         ]
         [       bucket[0]       ]
         [          ...          ]
         [   bucket[nbucket-1]   ]
         [       chain[0]        ]
         [          ...          ]
         [    chain[nchain-1]    ] */

    map->l_nbuckets = *hash++;
    hash++;
    map->l_buckets = hash;
    hash += map->l_nbuckets;
    map->l_chain = hash;
}

static void * __heap_base = NULL;

static ElfW(Addr) __get_heap_base (size_t size)
{
    if (__heap_base == (void *) -1)
        return 0;

    if (!__heap_base &&
        !(__heap_base = pal_config.heap_base)) {
        __heap_base = (void *) -1;
        return 0;
    }

    return (ElfW(Addr)) (__heap_base -= ALLOC_ALIGNUP(size));
}

/* Map in the shared object NAME, actually located in REALNAME, and already
   opened on FD */
struct link_map *
map_elf_object_by_handle (PAL_HANDLE handle, enum object_type type,
                          void * fbp, size_t fbp_len,
                          bool do_copy_dyn)
{
    struct link_map * l = new_elf_object(_DkStreamRealpath(handle), type);
    const char * errstring = NULL;
    int errval = 0;
    int ret;

    if (handle == NULL) {
        errstring = "cannot stat shared object";
        errval = PAL_ERROR_INVAL;
call_lose:
        printf("%s (%d)\n", errstring, PAL_STRERROR(errval));
        return NULL;
    }

    /* This is the ELF header.  We read it in `open_verify'.  */
    const ElfW(Ehdr) * header = (void *) fbp;

    /* Extract the remaining details we need from the ELF header
       and then read in the program header table.  */
    int e_type = header->e_type;
    l->l_entry = header->e_entry;
    l->l_phnum = header->e_phnum;

    size_t maplength = header->e_phnum * sizeof (ElfW(Phdr));
    ElfW(Phdr) * phdr;

    if (header->e_phoff + maplength <= (size_t) fbp_len) {
        phdr = (void *) (fbp + header->e_phoff);
    } else {
        phdr = (ElfW(Phdr) *) malloc (maplength);

        if ((ret = _DkStreamRead(handle, header->e_phoff, maplength, phdr,
                                 NULL, 0)) < 0) {
            errstring = "cannot read file data";
            errval = ret;
            goto call_lose;
        }
    }

    /* Presumed absent PT_GNU_STACK.  */
    //uint_fast16_t stack_flags = PF_R|PF_W|PF_X;

    /* Scan the program header table, collecting its load commands.  */
    struct loadcmd {
        ElfW(Addr) mapstart, mapend, dataend, allocend;
        off_t mapoff;
        int prot;
    } loadcmds[l->l_phnum], *c;

    size_t nloadcmds = 0;
    bool has_holes = false;

    /* The struct is initialized to zero so this is not necessary:
       l->l_ld = 0;
       l->l_phdr = 0;
       l->l_addr = 0; */

    const ElfW(Phdr) * ph;
    for (ph = phdr; ph < &phdr[l->l_phnum]; ++ph)
        switch (ph->p_type)
        {
            /* These entries tell us where to find things once the file's
               segments are mapped in.  We record the addresses it says
               verbatim, and later correct for the run-time load address.  */
            case PT_DYNAMIC:
                l->l_ld = (void *) ph->p_vaddr;
                l->l_ldnum = ph->p_memsz / sizeof (ElfW(Dyn));
                break;

            case PT_PHDR:
                l->l_phdr = (void *) ph->p_vaddr;
                break;

            case PT_LOAD:
                /* A load command tells us to map in part of the file.
                   We record the load commands and process them all later.  */
                if (__builtin_expect ((ph->p_align & allocshift) != 0, 0)) {
                    errstring = "ELF load command alignment not aligned";
                    errval = ENOMEM;
                    goto call_lose;
                }

                if (__builtin_expect (((ph->p_vaddr - ph->p_offset)
                                       & (ph->p_align - 1)) != 0, 0)) {
                    errstring = "\
                        ELF load command address/offset not properly aligned";
                    errval = ENOMEM;
                    goto call_lose;
                }

                c = &loadcmds[nloadcmds++];
                c->mapstart = ALLOC_ALIGNDOWN(ph->p_vaddr);
                c->mapend = ALLOC_ALIGNUP(ph->p_vaddr + ph->p_filesz);
                c->dataend = ph->p_vaddr + ph->p_filesz;
                c->allocend = ph->p_vaddr + ph->p_memsz;
                c->mapoff = ALLOC_ALIGNDOWN(ph->p_offset);

                /* Determine whether there is a gap between the last segment
                   and this one.  */
                if (nloadcmds > 1 && c[-1].mapend != c->mapstart)
                    has_holes = true;

                /* Optimize a common case.  */
#if (PF_R | PF_W | PF_X) == 7 && (PROT_READ | PROT_WRITE | PROT_EXEC) == 7
                c->prot = (PF_TO_PROT
                          >> ((ph->p_flags & (PF_R | PF_W | PF_X)) * 4)) & 0xf;
#else
                c->prot = 0;
                if (ph->p_flags & PF_R)
                    c->prot |= PROT_READ;
                if (ph->p_flags & PF_W)
                    c->prot |= PROT_WRITE;
                if (ph->p_flags & PF_X)
                    c->prot |= PROT_EXEC;
#endif
                break;

            case PT_TLS:
                if (ph->p_memsz == 0)
                    /* Nothing to do for an empty segment.  */
                    break;

            case PT_GNU_STACK:
                //stack_flags = ph->p_flags;
                break;

            case PT_GNU_RELRO:
                l->l_relro_addr = ph->p_vaddr;
                l->l_relro_size = ph->p_memsz;
                break;
        }

    if (__builtin_expect (nloadcmds == 0, 0)) {
        /* This only happens for a bogus object that will be caught with
           another error below.  But we don't want to go through the
           calculations below using NLOADCMDS - 1.  */
        errstring = "object file has no loadable segments";
        goto call_lose;
    }

    /* Now process the load commands and map segments into memory.  */
    c = loadcmds;

    /* Length of the sections to be loaded.  */
    maplength = loadcmds[nloadcmds - 1].allocend - c->mapstart;

#define APPEND_WRITECOPY(prot) ((prot)|PAL_PROT_WRITECOPY)

    if (__builtin_expect (e_type, ET_DYN) == ET_DYN) {
        /* This is a position-independent shared object.  We can let the
           kernel map it anywhere it likes, but we must have space for all
           the segments in their specified positions relative to the first.
           So we map the first segment without MAP_FIXED, but with its
           extent increased to cover all the segments.  Then we remove
           access from excess portion, and there is known sufficient space
           there to remap from the later segments.

           As a refinement, sometimes we have an address that we would
           prefer to map such objects at; but this is only a preference,
           the OS can do whatever it likes. */
        ElfW(Addr) mappref = __get_heap_base(maplength);

        /* Remember which part of the address space this object uses.  */
        errval = _DkStreamMap(handle, (void **) &mappref,
                              APPEND_WRITECOPY(c->prot), c->mapoff,
                              maplength);

        if (__builtin_expect (errval < 0, 0)) {
            errval = -errval;
map_error:
            errstring = "failed to map segment from shared object";
            goto call_lose;
        }

        l->l_map_start = mappref;
        l->l_map_end = l->l_map_start + maplength;
        l->l_addr = l->l_map_start - c->mapstart;

        if (has_holes)
            /* Change protection on the excess portion to disallow all access;
               the portions we do not remap later will be inaccessible as if
               unallocated.  Then jump into the normal segment-mapping loop to
               handle the portion of the segment past the end of the file
               mapping.  */
            _DkVirtualMemoryProtect((caddr_t) (l->l_addr + c->mapend),
                                    loadcmds[nloadcmds - 1].mapstart - c->mapend,
                                    PAL_PROT_NONE);

        goto postmap;
    }

    /* Remember which part of the address space this object uses.  */
    l->l_map_start = c->mapstart + l->l_addr;
    l->l_map_end = l->l_map_start + maplength;

    while (c < &loadcmds[nloadcmds]) {
        if (c->mapend > c->mapstart) {
            /* Map the segment contents from the file.  */
            void * mapaddr = (void *) (l->l_addr + c->mapstart);
            int rv;

            if ((rv = _DkStreamMap(handle, &mapaddr, APPEND_WRITECOPY(c->prot),
                                   c->mapoff, c->mapend - c->mapstart)) < 0) {
                goto map_error;
            }
        }

postmap:
        if (c->prot & PROT_EXEC) {
            l->l_text_start = l->l_addr + c->mapstart;
            l->l_text_end = l->l_addr + c->mapend;
        }

        if (c->prot & PROT_WRITE) {
            l->l_data_start = l->l_addr + c->mapstart;
            l->l_data_end = l->l_addr + c->mapend;
        }

        if (l->l_phdr == 0
            && (ElfW(Off)) c->mapoff <= header->e_phoff
            && ((size_t) (c->mapend - c->mapstart + c->mapoff)
                >= header->e_phoff + header->e_phnum * sizeof (ElfW(Phdr))))
            /* Found the program header in this segment.  */
            l->l_phdr = (void *) (c->mapstart + header->e_phoff - c->mapoff);

        if (c->allocend > c->dataend) {
            /* Extra zero pages should appear at the end of this segment,
               after the data mapped from the file.   */
            ElfW(Addr) zero, zeroend, zerosec;

            zero = l->l_addr + c->dataend;
            zeroend = ALLOC_ALIGNUP(l->l_addr + c->allocend);
            zerosec = ALLOC_ALIGNUP(zero);

            if (zeroend < zerosec)
                /* All the extra data is in the last section of the segment.
                   We can just zero it.  */
                zerosec = zeroend;

            if (zerosec > zero) {
                /* Zero the final part of the last section of the segment.  */
                if (__builtin_expect ((c->prot & PROT_WRITE) == 0, 0))
                {
                    /* Dag nab it.  */
                    if (_DkVirtualMemoryProtect((void *) ALLOC_ALIGNDOWN(zero),
                                                allocsize,
                                                c->prot|PAL_PROT_WRITE) < 0) {
                        errstring = "cannot change memory protections";
                        goto call_lose;
                    }
                }
                memset ((void *) zero, '\0', zerosec - zero);
                if (__builtin_expect ((c->prot & PROT_WRITE) == 0, 0))
                    _DkVirtualMemoryProtect((void *) ALLOC_ALIGNDOWN(zero),
                                            allocsize, c->prot);
            }

            if (zeroend > zerosec) {
                /* Map the remaining zero pages in from the zero fill FD. */
                void * mapat = (void *) zerosec;
                errval = _DkVirtualMemoryAlloc(&mapat, zeroend - zerosec,
                                               0, c->prot);
                if (__builtin_expect (errval < 0, 0)) {
                    errstring = "cannot map zero-fill allocation";
                    goto call_lose;
                }
            }
        }

        ++c;
    }

    if (l->l_ld == 0) {
        if (__builtin_expect (e_type == ET_DYN, 0)) {
            errstring = "object file has no dynamic section";
            goto call_lose;
        }
    } else {
        l->l_ld = (ElfW(Dyn) *) ((ElfW(Addr)) l->l_ld + l->l_addr);
    }

    l->l_real_ld = l->l_ld;

    if (do_copy_dyn)
        l->l_ld = remalloc(l->l_ld, sizeof(ElfW(Dyn)) * l->l_ldnum);

    elf_get_dynamic_info(l->l_ld, l->l_info, l->l_addr);

    /* When we profile the SONAME might be needed for something else but
       loading.  Add it right away.  */
    if (l->l_info[DT_STRTAB] && l->l_info[DT_SONAME])
        l->l_soname =  (char *) (D_PTR (l->l_info[DT_STRTAB])
                             + D_PTR (l->l_info[DT_SONAME]));

    if (l->l_phdr == NULL) {
        /* The program header is not contained in any of the segments.
           We have to allocate memory ourself and copy it over from out
           temporary place.  */
        ElfW(Phdr) * newp = (ElfW(Phdr) *) malloc (header->e_phnum
                                                   * sizeof (ElfW(Phdr)));
        if (!newp) {
            errstring = "cannot allocate memory for program header";
            goto call_lose;
        }

        l->l_phdr = memcpy(newp, phdr,
                           header->e_phnum * sizeof (ElfW(Phdr)));
    } else {
        /* Adjust the PT_PHDR value by the runtime load address.  */
        l->l_phdr = (ElfW(Phdr) *) ((ElfW(Addr)) l->l_phdr + l->l_addr);
    }

    l->l_entry += l->l_addr;

    /* Set up the symbol hash table.  */
    setup_elf_hash (l);

    return l;
}

int check_elf_object (PAL_HANDLE handle)
{
#define ELF_MAGIC_SIZE EI_CLASS
    unsigned char buffer[ELF_MAGIC_SIZE];

    int len = _DkStreamRead(handle, 0, ELF_MAGIC_SIZE, buffer, NULL, 0);

    if (__builtin_expect (len < 0, 0))
        return -len;

    if (__builtin_expect (len < ELF_MAGIC_SIZE, 0))
        return -PAL_ERROR_INVAL;

    ElfW(Ehdr) * ehdr = (ElfW(Ehdr) *) buffer;

    static const unsigned char expected[EI_CLASS] =
    {
        [EI_MAG0] = ELFMAG0,
        [EI_MAG1] = ELFMAG1,
        [EI_MAG2] = ELFMAG2,
        [EI_MAG3] = ELFMAG3,
    };

    /* See whether the ELF header is what we expect.  */
    if (__builtin_expect(memcmp(ehdr->e_ident, expected, ELF_MAGIC_SIZE) !=
                         0, 0))
        return -PAL_ERROR_INVAL;

    return 0;
}

void free_elf_object (struct link_map * map)
{
    /* unmap the exec_map */
    _DkVirtualMemoryFree((void *) map->l_map_start,
                         map->l_map_end - map->l_map_start);

    pal_sec_info._r_debug->r_state = RT_DELETE;
    pal_sec_info._dl_debug_state();

    if (map->l_prev)
        map->l_prev->l_next = map->l_next;
    if (map->l_next)
        map->l_next->l_prev = map->l_prev;

    pal_sec_info._r_debug->r_state = RT_CONSISTENT;
    pal_sec_info._dl_debug_state();

    if (loaded_libraries == map)
        loaded_libraries = map->l_next;

    free(map);
}

/* Map in the shared object file loaded from URI.  */
int load_elf_object (const char * uri, enum object_type type)
{
    PAL_HANDLE handle;
    /* First we open the file by uri, as the regular file handles */
    int ret = _DkStreamOpen(&handle, uri, PAL_ACCESS_RDONLY,
                            0, 0, 0);
    if (ret < 0)
        return ret;

    if (type == OBJECT_EXEC) {
        struct link_map *map = loaded_libraries, *next;
        while (map) {
            next = map->l_next;
            if (map->l_type == type)
                free_elf_object(map);
            map = next;
        }
    }

    ret = load_elf_object_by_handle(handle, type);

    _DkObjectClose(handle);
    return ret;
}

static int relocate_elf_object (struct link_map *l);

int load_elf_object_by_handle (PAL_HANDLE handle, enum object_type type)
{
    char fb[FILEBUF_SIZE];
    char * errstring;
    int ret = 0;

    /* Now we will start verify the file as a ELF header. This part of code
       is borrow from open_verify() */
    ElfW(Ehdr) * ehdr = (ElfW(Ehdr) *) &fb;
    ElfW(Phdr) * phdr = NULL;
    int phdr_malloced = 0;

    int len = _DkStreamRead(handle, 0, FILEBUF_SIZE, &fb, NULL, 0);

    if (__builtin_expect (len < sizeof(ElfW(Ehdr)), 0)) {
        errstring = "ELF file with a strange size";
        goto verify_failed;
    }

#define ELF32_CLASS ELFCLASS32
#define ELF64_CLASS ELFCLASS64

    static const unsigned char expected[EI_NIDENT] =
    {
        [EI_MAG0] = ELFMAG0,
        [EI_MAG1] = ELFMAG1,
        [EI_MAG2] = ELFMAG2,
        [EI_MAG3] = ELFMAG3,
        [EI_CLASS] = ELFW(CLASS),
        [EI_DATA] = byteorder,
        [EI_VERSION] = EV_CURRENT,
        [EI_OSABI] = 0,
    };

#define ELFOSABI_LINUX		3	/* Linux.  */

    int maplength;

    /* See whether the ELF header is what we expect.  */
    if (__builtin_expect(
        memcmp(ehdr->e_ident, expected, EI_OSABI) != 0 || (
        ehdr->e_ident[EI_OSABI] != ELFOSABI_SYSV &&
        ehdr->e_ident[EI_OSABI] != ELFOSABI_LINUX), 0)) {
        errstring = "ELF file with invalid header";
        goto verify_failed;
    }

    /* Chia-Che 11/23/13: Removing other checks, comparing the header
       should be enough */

    maplength = ehdr->e_phnum * sizeof (ElfW(Phdr));
    /* if e_phoff + maplength is smaller than the data read */
    if (ehdr->e_phoff + maplength <= (size_t) len) {
        phdr = (void *) (&fb + ehdr->e_phoff);
    } else {
        /* ...otherwise, we have to read again */
        phdr = malloc (maplength);
        phdr_malloced = 1;

        ret = _DkStreamRead(handle, ehdr->e_phoff, maplength, phdr, NULL, 0);

        if (ret < 0 || ret != maplength) {
            errstring = "cannot read file data";
            goto verify_failed;
        }
    }

    pal_sec_info._r_debug->r_state = RT_ADD;
    pal_sec_info._dl_debug_state();

    struct link_map * map;

    if (!(map = map_elf_object_by_handle(handle, type, &fb, len, true))) {
        errstring = "unexpected failure";
        goto verify_failed;
    }

    relocate_elf_object(map);

    if (map->l_type == OBJECT_EXEC)
        exec_map = map;

    if (map->l_type == OBJECT_PRELOAD && map->l_entry)
        run_preload = true;

    struct link_map * prev = NULL, ** pprev = &loaded_libraries,
                    * next = loaded_libraries;

    while (next) {
        prev = next;
        pprev = &next->l_next;
        next = next->l_next;
    }

    *pprev = map;
    map->l_prev = prev;
    map->l_next = NULL;

    pal_sec_info._r_debug->r_state = RT_CONSISTENT;
    pal_sec_info._dl_debug_state();

    return 0;

verify_failed:

    if (phdr && phdr_malloced)
        free(phdr);

    printf("%s\n", errstring);
    return ret;
}

struct sym_val {
    ElfW(Sym) *s;
    struct link_map *m;
};

/* This is the hashing function specified by the ELF ABI.  In the
   first five operations no overflow is possible so we optimized it a
   bit.  */
unsigned long int elf_hash (const char *name_arg)
{
    const unsigned char *name = (const unsigned char *) name_arg;
    unsigned long int hash = 0;

    if (*name == '\0')
        return hash;

    hash = *name++;
    if (*name == '\0')
        return hash;

    hash = (hash << 4) + *name++;
    if (*name == '\0')
        return hash;

    hash = (hash << 4) + *name++;
    if (*name == '\0')
        return hash;

    hash = (hash << 4) + *name++;
    if (*name == '\0')
        return hash;

    hash = (hash << 4) + *name++;
    while (*name != '\0') {
        unsigned long int hi;
        hash = (hash << 4) + *name++;
        hi = hash & 0xf0000000;

        /*
         * The algorithm specified in the ELF ABI is as follows:
         * if (hi != 0)
         * hash ^= hi >> 24;
         * hash &= ~hi;
         * But the following is equivalent and a lot faster, especially on
         *  modern processors.
         */

        hash ^= hi;
        hash ^= hi >> 24;
    }
    return hash;
}

ElfW(Sym) *
do_lookup_map (ElfW(Sym) * ref, const char * undef_name,
               const uint_fast32_t hash, unsigned long int elf_hash,
               const struct link_map * map)
{
    /* These variables are used in the nested function.  */
    Elf_Symndx symidx;
    ElfW(Sym) * sym;
    /* The tables for this map.  */
    ElfW(Sym) * symtab = (void *) D_PTR (map->l_info[DT_SYMTAB]);
    const char * strtab = (const void *) D_PTR (map->l_info[DT_STRTAB]);

    /* Nested routine to check whether the symbol matches.  */
    ElfW(Sym) * check_match (ElfW(Sym) *sym)
    {
        unsigned int stt = ELFW(ST_TYPE) (sym->st_info);
        assert (ELF_RTYPE_CLASS_PLT == 1);

        if (__builtin_expect ((sym->st_value == 0 /* No value.  */
                               && stt != STT_TLS)
            || sym->st_shndx == SHN_UNDEF, 0))
            return NULL;

        /* Ignore all but STT_NOTYPE, STT_OBJECT, STT_FUNC,
           STT_COMMON, STT_TLS, and STT_GNU_IFUNC since these are no
           code/data definitions.  */
#define ALLOWED_STT     \
        ((1 << STT_NOTYPE) | (1 << STT_OBJECT) | (1 << STT_FUNC)        \
       | (1 << STT_COMMON) | (1 << STT_TLS)    | (1 << STT_GNU_IFUNC))

        if (__builtin_expect (((1 << stt) & ALLOWED_STT) == 0, 0))
            return NULL;

        if (sym != ref && memcmp(strtab + sym->st_name, undef_name,
                                 strlen(undef_name)))
            /* Not the symbol we are looking for.  */
            return NULL;

        /* There cannot be another entry for this symbol so stop here.  */
        return sym;
    }

    const ElfW(Addr) * bitmask = map->l_gnu_bitmask;

    if (__builtin_expect (bitmask != NULL, 1)) {
        ElfW(Addr) bitmask_word = bitmask[(hash / __ELF_NATIVE_CLASS)
                                          & map->l_gnu_bitmask_idxbits];

        unsigned int hashbit1 = hash & (__ELF_NATIVE_CLASS - 1);
        unsigned int hashbit2 = (hash >> map->l_gnu_shift)
                                & (__ELF_NATIVE_CLASS - 1);

        if (__builtin_expect ((bitmask_word >> hashbit1)
                            & (bitmask_word >> hashbit2) & 1, 0)) {
            Elf32_Word bucket = map->l_gnu_buckets
                                    [hash % map->l_nbuckets];

            if (bucket != 0) {
                const Elf32_Word *hasharr = &map->l_gnu_chain_zero[bucket];

                do
                    if (((*hasharr ^ hash) >> 1) == 0) {
                        symidx = hasharr - map->l_gnu_chain_zero;
                        sym = check_match (&symtab[symidx]);
                        if (sym != NULL)
                            return sym;
                    }
                while ((*hasharr++ & 1u) == 0);
            }
        }

        /* No symbol found.  */
        symidx = SHN_UNDEF;
    } else {
        /* Use the old SysV-style hash table.  Search the appropriate
           hash bucket in this object's symbol table for a definition
           for the same symbol name.  */
        for (symidx = map->l_buckets[elf_hash % map->l_nbuckets];
             symidx != STN_UNDEF;
             symidx = map->l_chain[symidx]) {
            sym = check_match (&symtab[symidx]);
            if (sym != NULL)
                return sym;
        }
    }

    return NULL;
}

/* Inner part of the lookup functions.  We return a value > 0 if we
   found the symbol, the value 0 if nothing is found and < 0 if
   something bad happened.  */
static int do_lookup (const char * undef_name, ElfW(Sym) * ref,
                      struct sym_val * result)
{
    const uint_fast32_t fast_hash = elf_fast_hash(undef_name);
    const long int hash = elf_hash(undef_name);

    assert(rtld_map);

    ElfW(Sym) * sym = do_lookup_map (ref, undef_name, fast_hash, hash,
                                     rtld_map);

    if (sym == NULL)
        return 0;

    switch (__builtin_expect (ELFW(ST_BIND) (sym->st_info), STB_GLOBAL)) {
        case STB_WEAK:
            /* Weak definition.  Use this value if we don't find another. */
            if (!result->s) {
                result->s = sym;
                result->m = (struct link_map *) rtld_map;
            }
            break;

            /* FALLTHROUGH */
        case STB_GLOBAL:
        case STB_GNU_UNIQUE:
            /* success: */
            /* Global definition.  Just what we need.  */
            result->s = sym;
            result->m = (struct link_map *) rtld_map;
            return 1;

        default:
            /* Local symbols are ignored.  */
            break;
    }

    /* We have not found anything until now.  */
    return 0;
}

/* Search loaded objects' symbol tables for a definition of the symbol
   UNDEF_NAME, perhaps with a requested version for the symbol.

   We must never have calls to the audit functions inside this function
   or in any function which gets called.  If this would happen the audit
   code might create a thread which can throw off all the scope locking.  */
struct link_map * lookup_symbol (const char * undef_name, ElfW(Sym) ** ref)
{
    struct sym_val current_value = { NULL, NULL };

    do_lookup(undef_name, *ref, &current_value);

    if (__builtin_expect (current_value.s == NULL, 0)) {
        *ref = NULL;
        return NULL;
    }

    *ref = current_value.s;
    return current_value.m;
}

static int protect_relro (struct link_map * l)
{
    ElfW(Addr) start = ALLOC_ALIGNDOWN(l->l_addr + l->l_relro_addr);
    ElfW(Addr) end = ALLOC_ALIGNUP(l->l_addr + l->l_relro_addr +
                                   l->l_relro_size);

    if (start != end)
        _DkVirtualMemoryProtect((void *) start, end - start, PAL_PROT_READ);
    return 0;
}

static int relocate_elf_object (struct link_map * l)
{
   struct textrels {
        ElfW(Addr) start;
        ElfW(Addr) len;
        int prot;
        struct textrels * next;
    } * textrels = NULL;
    int ret;
    const ElfW(Phdr) * ph;

    for (ph = l->l_phdr ; ph < &l->l_phdr[l->l_phnum] ; ph++)
        if (ph->p_type == PT_LOAD && (ph->p_flags & PF_W) == 0) {
            struct textrels * r = malloc(sizeof(struct textrels));
            r->start = ALLOC_ALIGNDOWN(ph->p_vaddr) + l->l_addr;
            r->len = ALLOC_ALIGNUP(ph->p_vaddr + ph->p_memsz)
                     - ALLOC_ALIGNDOWN(ph->p_vaddr);

            ret = _DkVirtualMemoryProtect((void *) r->start, r->len,
                                          PAL_PROT_READ|PAL_PROT_WRITE);
            if (ret < 0)
                return ret;

#if (PF_R | PF_W | PF_X) == 7 && (PROT_READ | PROT_WRITE | PROT_EXEC) == 7
            r->prot = (PF_TO_PROT
                      >> ((ph->p_flags & (PF_R | PF_W | PF_X)) * 4)) & 0xf;
#else
            r->prot = 0;
            if (ph->p_flags & PF_R)
                r->prot |= PROT_READ;
            if (ph->p_flags & PF_W)
                r->prot |= PROT_WRITE;
            if (ph->p_flags & PF_X)
                r->prot |= PROT_EXEC;
#endif
            r->next = textrels;
            textrels = r;
        }

    /* Do the actual relocation of the object's GOT and other data.  */
    if (l->l_type == OBJECT_EXEC)
        ELF_DYNAMIC_SCAN(l->l_info, l->l_addr);
    else
        ELF_DYNAMIC_RELOCATE(l->l_info, l->l_addr);

    while (textrels) {
       ret = _DkVirtualMemoryProtect((void *) textrels->start, textrels->len,
                                     textrels->prot);
        if (ret < 0)
            return ret;

        struct textrels * next = textrels->next;
        free(textrels);
        textrels = next;
    }

    /* In case we can protect the data now that the relocations are
       done, do it.  */
    if (l->l_type != OBJECT_EXEC && l->l_relro_size != 0)
        if ((ret = protect_relro(l)) < 0)
            return ret;

    if (l->l_type == OBJECT_PRELOAD && pal_config.syscall_sym_name) {
        uint_fast32_t fast_hash = elf_fast_hash(pal_config.syscall_sym_name);
        long int hash = elf_hash(pal_config.syscall_sym_name);
        ElfW(Sym) * sym = NULL;

        sym = do_lookup_map(NULL, pal_config.syscall_sym_name, fast_hash,
                            hash, l);

        if (sym) {
            pal_config.syscall_sym_addr =
                    (void *) (l->l_addr + sym->st_value);
        }
    }

    l->l_relocated = true;
    return 0;
}

void setup_pal_map (const char * realname, ElfW(Dyn) ** dyn, ElfW(Addr) addr)
{
    assert (loaded_libraries == NULL);

    const ElfW(Ehdr) * header = (void *) addr;
    struct link_map * l = new_elf_object(realname, OBJECT_RTLD);
    memcpy(l->l_info, dyn, sizeof(l->l_info));
    l->l_real_ld = l->l_ld = (void *) elf_machine_dynamic();
    l->l_addr  = addr;
    l->l_entry = header->e_entry;
    l->l_phdr  = (void *) (addr + header->e_phoff);
    l->l_phnum = header->e_phnum;
    l->l_relocated = true;
    l->l_soname = "libpal.so";
    l->l_text_start = (ElfW(Addr)) &text_start;
    l->l_text_end   = (ElfW(Addr)) &text_end;
    l->l_data_start = (ElfW(Addr)) &data_start;
    l->l_data_end   = (ElfW(Addr)) &data_end;
    setup_elf_hash(l);

    void * begin_hole = (void *) ALLOC_ALIGNUP(l->l_text_end);
    void * end_hole = (void *) ALLOC_ALIGNDOWN(l->l_data_start);

    /* Usually the test segment and data segment of a loaded library has
       a gap between them. Need to fill the hole with a empty area */
    if (begin_hole < end_hole) {
        void * addr = begin_hole;
        _DkVirtualMemoryAlloc(&addr, end_hole - begin_hole,
                              PAL_ALLOC_RESERVE, PAL_PROT_NONE);
    }

    /* Set up debugging before the debugger is notified for the first time.  */
    if (l->l_info[DT_DEBUG] != NULL)
        l->l_info[DT_DEBUG]->d_un.d_ptr = (ElfW(Addr)) &pal_r_debug;

    l->l_prev = l->l_next = NULL;
    rtld_map = l;
    loaded_libraries = l;

    if (!pal_sec_info._r_debug) {
        pal_r_debug.r_version = 1;
        pal_r_debug.r_brk = (ElfW(Addr)) &pal_dl_debug_state;
        pal_r_debug.r_ldbase = addr;
        pal_r_debug.r_map = loaded_libraries;
        pal_sec_info._r_debug = &pal_r_debug;
        pal_sec_info._dl_debug_state = &pal_dl_debug_state;
    } else {
        pal_sec_info._r_debug->r_state = RT_ADD;
        pal_sec_info._dl_debug_state();

        if (pal_sec_info._r_debug->r_map) {
            l->l_prev = pal_sec_info._r_debug->r_map;
            pal_sec_info._r_debug->r_map->l_next = l;
        } else {
            pal_sec_info._r_debug->r_map = loaded_libraries;
        }

        pal_sec_info._r_debug->r_state = RT_CONSISTENT;
        pal_sec_info._dl_debug_state();
    }
}

void start_execution (int argc, const char ** argv)
{
    /* First we will try to run all the preloaded libraries which come with
       entry points */
    if (exec_map) {
        __pal_control.executable_begin = (void *) exec_map->l_map_start;
        __pal_control.executable_end = (void *) exec_map->l_map_end;
    }

    int ret = 0;

    if (!run_preload)
        goto NO_PRELOAD;

    /* Let's count the number of cookies, first we will have argc & argv */
    size_t ncookies = argc + 2; /* 1 for argc, argc + 1 for argv */

    /* Then we count envp */
    for (const char ** e = pal_config.environments; *e; e++)
        ncookies++;

    ncookies++; /* for NULL-end */

    size_t cookiesz = sizeof(unsigned long int) * ncookies
                      + sizeof(ElfW(auxv_t)) * 6
                      + sizeof(void *) * 3 + 16;

    unsigned long int * cookies = __alloca(cookiesz);

    /* Let's copy the cookies */
    cookies[0] = (unsigned long int) argc;
    size_t i;

    for (i = 0 ; i <= argc ; i++)
        cookies[i + 1] = (unsigned long int) argv[i];

    size_t cnt = argc + 2;

    if (pal_config.environments)
        for (i = 0 ; pal_config.environments[i]; i++)
            cookies[cnt++] = (unsigned long int) pal_config.environments[i];

    cookies[cnt++] = 0;

    ElfW(auxv_t) * auxv = (ElfW(auxv_t) *) &cookies[cnt];

    auxv[0].a_type = AT_PHDR;
    auxv[0].a_un.a_val = exec_map ?
                         (__typeof(auxv[1].a_un.a_val)) exec_map->l_phdr : 0;

    auxv[1].a_type = AT_PHNUM;
    auxv[1].a_un.a_val = exec_map ? exec_map->l_phnum : 0;

    auxv[2].a_type = AT_PAGESZ;
    auxv[2].a_un.a_val = __pal_control.pagesize;

    auxv[3].a_type = AT_ENTRY;
    auxv[3].a_un.a_val = exec_map ? exec_map->l_entry : 0;

    auxv[4].a_type = AT_BASE;
    auxv[4].a_un.a_val = exec_map ? exec_map->l_addr : 0;

    auxv[5].a_type = AT_NULL;

    void * stack = (void *) &auxv[6] + sizeof(uint64_t);
    ((uint64_t *) stack)[-1] = 0;

    /* the previous cookiesz might be wrong, we have to recalculate it */
    cookiesz = (PAL_PTR) &auxv[6] - (PAL_PTR) cookies;

    for (struct link_map * l = loaded_libraries ; l ; l = l->l_next) {
        if (l->l_type != OBJECT_PRELOAD || !l->l_entry)
            continue;

#if defined(__x86_64__)
        asm volatile (
              "movq %%rsp, 16(%3)\r\n"
              "movq %2, %%rsp\r\n"

              "leaq .LRET1(%%rip), %%rbx\r\n"
              "movq %%rbx, 8(%3)\r\n"

              "movq %%rbp, 0(%3)\r\n"

              "jmp *%1\r\n"

              ".LRET1:\r\n"
              "popq %%rsp\r\n"

              : "=a" (ret)

              : "a"(l->l_entry),
                "b"(cookies),
                "S"(stack)

              : "rcx", "rdx", "r8", "r9", "r10", "r11", "memory");
#else
# error "architecture not supported"
#endif

        if (ret < 0)
            _DkThreadExit(ret);
    }

NO_PRELOAD:
    if (exec_map && exec_map->l_entry) {
        /* This part is awesome. Don't risk changing it!! */
#if defined(__x86_64__)
        ret = ((int (*) (int, const char **, const char **))
               exec_map->l_entry) (argc, argv, pal_config.environments);
#else
# error "architecture not supported"
#endif
    }

    /* If they ever return here, we will be exiting */
    _DkProcessExit(ret);

    /* Control should not get here */
    assert(0);
}
