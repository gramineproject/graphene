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
 * shim_rtld.c
 *
 * This file contains codes for dynamic loading of ELF binaries in library OS.
 * It's espeically used for loading interpreter (ld.so, in general) and
 * optimization of execve.
 * Most of the source codes are imported from GNU C library.
 */

#include <asm/mman.h>
#include <asm/prctl.h>
#include <errno.h>
#include <shim_checkpoint.h>
#include <shim_fs.h>
#include <shim_handle.h>
#include <shim_internal.h>
#include <shim_profile.h>
#include <shim_table.h>
#include <shim_thread.h>
#include <shim_utils.h>
#include <shim_vdso.h>
#include <shim_vma.h>

#include "elf.h"
#include "ldsodefs.h"

#ifndef DT_THISPROCNUM
#define DT_THISPROCNUM 0
#endif

typedef ElfW(Word) Elf_Symndx;

#define BOOKKEEP_INTERNAL_OBJ 0

enum object_type {
    OBJECT_INTERNAL = 0,
    OBJECT_LOAD     = 1,
    OBJECT_MAPPED   = 2,
    OBJECT_REMAP    = 3,
    OBJECT_USER     = 4,
    OBJECT_VDSO     = 5,
};

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

    ElfW(Addr) l_addr;       /* Base address shared object is loaded at. */
    const char* l_name;      /* Absolute file name object was found in.  */
    ElfW(Dyn)* l_real_ld;    /* Dynamic section of the shared object.    */
    struct link_map* l_next; /* Chain of loaded objects.  */
    struct link_map* l_prev;

    /* All following members are internal to the dynamic linker.
       They may change without notice.  */
    ElfW(Dyn)* l_ld;
    char* l_soname;

    ElfW(Dyn)*
        l_info[DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM + DT_EXTRANUM + DT_VALNUM + DT_ADDRNUM];
    const ElfW(Phdr)* l_phdr;  /* Pointer to program header table in core.  */
    ElfW(Addr) l_entry;        /* Entry point location.  */
    ElfW(Half) l_phnum;        /* Number of program header entries.  */
    ElfW(Half) l_ldnum;        /* Number of dynamic segment entries.  */

    /* Start and finish of memory map for this object.  l_map_start
       need not be the same as l_addr.  */
    ElfW(Addr) l_map_start, l_map_end;

    bool l_resolved;
    ElfW(Addr) l_resolved_map;
    const char* l_interp_libname;
    ElfW(Addr) l_main_entry;

    /* Information used to change permission after the relocations are
       done.   */
    ElfW(Addr) l_relro_addr;
    size_t l_relro_size;

    /* For DT_HASH */
    Elf_Symndx l_nbuckets;
    const Elf_Symndx* l_buckets;
    const Elf_Symndx* l_chain;

    /* For DT_GNU_HASH */
    Elf32_Word l_gnu_bitmask_idxbits;
    Elf32_Word l_gnu_shift;
    const ElfW(Addr)* l_gnu_bitmask;
    const Elf32_Word* l_gnu_buckets;
    const Elf32_Word* l_gnu_chain_zero;

    /* pointer to related file */
    struct shim_handle* l_file;

    enum object_type l_type;

#define MAX_LOADCMDS 4
    struct loadcmd {
        ElfW(Addr) mapstart, mapend, dataend, allocend;
        off_t mapoff;
        int prot, flags;
        struct shim_vma* vma;
    } loadcmds[MAX_LOADCMDS];
    int nloadcmds;

    struct textrel {
        ElfW(Addr) start, end;
        int prot;
        struct textrel* next;
    } * textrels;

#define MAX_LINKSYMS 32
    struct linksym {
        void* rel;
        ElfW(Sym)* sym;
        void* reloc;
    } linksyms[MAX_LINKSYMS];
    int nlinksyms;
};

struct link_map* lookup_symbol(const char* undef_name, ElfW(Sym)** ref);

static struct link_map* loaded_libraries = NULL;
static struct link_map* internal_map = NULL;
static struct link_map* interp_map = NULL;
static struct link_map* vdso_map = NULL;

/* This macro is used as a callback from the ELF_DYNAMIC_RELOCATE code.  */
static ElfW(Addr) resolve_map(const char** strtab, ElfW(Sym)** ref) {
    if (ELFW(ST_BIND)((*ref)->st_info) != STB_LOCAL) {
        struct link_map* l = lookup_symbol((*strtab) + (*ref)->st_name, ref);
        if (l) {
            *strtab = (const void*)D_PTR(l->l_info[DT_STRTAB]);
            return l->l_addr;
        }
    }
    return 0;
}

static int protect_page(struct link_map* l, void* addr, size_t size) {
    struct loadcmd* c = l->loadcmds;
    int prot          = 0;

    for (; c < &l->loadcmds[l->nloadcmds]; c++)
        if ((void*)l->l_addr + c->mapstart <= addr && addr + size <= (void*)l->l_addr + c->mapend)
            break;

    if (c < &l->loadcmds[l->nloadcmds])
        prot = c->prot;

    struct textrel* t    = l->textrels;
    struct textrel** loc = &l->textrels;

    for (; t; t = t->next) {
        if ((void*)t->start <= addr && addr + size <= (void*)t->end)
            return 0;

        loc = &t->next;
    }

    if ((prot & (PROT_READ | PROT_WRITE)) == (PROT_READ | PROT_WRITE)) {
        struct shim_vma_val vma;

        /* the actual protection of the vma might be changed */
        if (lookup_vma(addr, &vma) < 0)
            return 0;

        prot = vma.prot;

        if ((prot & (PROT_READ | PROT_WRITE)) == (PROT_READ | PROT_WRITE))
            return 0;
    }

    void* start = ALLOC_ALIGN_DOWN_PTR(addr);
    void* end   = ALLOC_ALIGN_UP_PTR(addr + size);

    if (!DkVirtualMemoryProtect(start, end - start, PAL_PROT_READ | PAL_PROT_WRITE | prot))
        return -PAL_ERRNO;

    if (!c)
        return 0;

    t = malloc(sizeof(struct textrel));
    if (!t)
        return -ENOMEM;

    t->start = (ElfW(Addr))start;
    t->end   = (ElfW(Addr))end;
    t->prot  = prot;
    t->next  = NULL;
    *loc     = t;

    return 0;
}

static int reprotect_map(struct link_map* l) {
    struct textrel* t = l->textrels;
    struct textrel* next;
    int ret = 0;

    while (t) {
        struct loadcmd* c = l->loadcmds;

        for (; c < &l->loadcmds[l->nloadcmds]; c++)
            if (l->l_addr + c->mapstart <= t->start && t->end <= l->l_addr + c->mapend)
                break;

        ElfW(Addr) start = t->start, end = t->end;
        int prot = t->prot;
        next     = t->next;
        free(t);
        t           = next;
        l->textrels = t;

        if (c && !DkVirtualMemoryProtect((void*)start, end - start, prot)) {
            ret = -PAL_ERRNO;
            break;
        }
    }

    return ret;
}

#define RESOLVE_MAP(strtab, ref)      resolve_map(strtab, ref)
#define PROTECT_PAGE(map, addr, size) protect_page(map, addr, size)
#define USE__THREAD                   0 /* disable TLS support */

#include "rel.h"

struct link_map* new_elf_object(const char* realname, int type) {
    struct link_map* new;

    new = (struct link_map*)malloc(sizeof(struct link_map));
    if (new == NULL)
        return NULL;

    /* We apparently expect this to be zeroed. */
    memset(new, 0, sizeof(struct link_map));
    new->l_name = realname;
    new->l_type = type;

    return new;
}

#include <endian.h>
#if __BYTE_ORDER == __BIG_ENDIAN
#define byteorder ELFDATA2MSB
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define byteorder ELFDATA2LSB
#else
#error "Unknown __BYTE_ORDER " __BYTE_ORDER
#define byteorder ELFDATANONE
#endif

#if __WORDSIZE == 32
#define FILEBUF_SIZE 512
#else
#define FILEBUF_SIZE 832
#endif

/* Cache the location of MAP's hash table.  */
void setup_elf_hash(struct link_map* map) {
    Elf_Symndx* hash;

    if (map->l_info[DT_ADDRTAGIDX(DT_GNU_HASH) + DT_NUM + DT_THISPROCNUM +
                                  DT_VERSIONTAGNUM + DT_EXTRANUM + DT_VALNUM
                   ] != NULL) {
        Elf32_Word* hash32 =
            (void*)D_PTR(map->l_info[DT_ADDRTAGIDX(DT_GNU_HASH) + DT_NUM + DT_THISPROCNUM +
                                     DT_VERSIONTAGNUM + DT_EXTRANUM + DT_VALNUM]);

        map->l_nbuckets = *hash32++;

        Elf32_Word symbias        = *hash32++;
        Elf32_Word bitmask_nwords = *hash32++;

        assert(IS_POWER_OF_2(bitmask_nwords));
        map->l_gnu_bitmask_idxbits = bitmask_nwords - 1;
        map->l_gnu_shift           = *hash32++;

        map->l_gnu_bitmask = (ElfW(Addr)*)hash32;
        hash32 += __ELF_NATIVE_CLASS / 32 * bitmask_nwords;

        map->l_gnu_buckets = hash32;
        hash32 += map->l_nbuckets;
        map->l_gnu_chain_zero = hash32 - symbias;

        return;
    }

    if (!map->l_info[DT_HASH])
        return;

    hash = (void*)D_PTR(map->l_info[DT_HASH]);

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

/* Map in the shared object NAME, actually located in REALNAME, and already
   opened on FD */
static struct link_map* __map_elf_object(struct shim_handle* file, const void* fbp, size_t fbp_len,
                                         void* addr, int type, struct link_map* remap) {
    ElfW(Phdr)* new_phdr = NULL;

    if (file && (!file->fs || !file->fs->fs_ops))
        return NULL;

    ssize_t (*read)(struct shim_handle*, void*, size_t) = file ? file->fs->fs_ops->read : NULL;
    int (*mmap)(struct shim_handle*, void**, size_t, int, int, off_t) =
        file ? file->fs->fs_ops->mmap : NULL;
    off_t (*seek)(struct shim_handle*, off_t, int) = file ? file->fs->fs_ops->seek : NULL;

    if (file && (!read || !mmap || !seek))
        return NULL;

    struct link_map* l =
        remap ? remap
              : new_elf_object(file ? (!qstrempty(&file->path) ? qstrgetstr(&file->path)
                                                               : qstrgetstr(&file->uri))
                                    : "",
                               type);

    if (!l)
        return NULL;

    const char* errstring __attribute__((unused)) = NULL;
    int ret;

    if (type != OBJECT_INTERNAL && type != OBJECT_VDSO && !file) {
        errstring = "shared object has to be backed by file";
        goto call_lose;
    }

    /* Scan the program header table, collecting its load commands.  */
    struct loadcmd* c = l->loadcmds;
    /* This is the ELF header.  We read it in `open_verify'.  */
    const ElfW(Ehdr)* header = fbp;

    /* Extract the remaining details we need from the ELF header
       and then read in the program header table.  */
    l->l_addr  = (ElfW(Addr))addr;
    l->l_entry = header->e_entry;
    int e_type = header->e_type;
    l->l_phnum = header->e_phnum;

    size_t maplength       = header->e_phnum * sizeof(ElfW(Phdr));
    const ElfW(Phdr)* phdr = (fbp + header->e_phoff);

    if (type == OBJECT_REMAP)
        goto do_remap;

    if (type == OBJECT_LOAD && header->e_phoff + maplength <= (size_t)fbp_len) {
        new_phdr = (ElfW(Phdr)*)malloc(maplength);
        if (!new_phdr) {
            errstring = "new_phdr malloc failure";
            goto call_lose;
        }
        if ((ret = (*seek)(file, header->e_phoff, SEEK_SET)) < 0 ||
            (ret = (*read)(file, new_phdr, maplength)) < 0) {
            errstring = "cannot read file data";
            goto call_lose;
        }
        phdr = new_phdr;
    }

    l->nloadcmds   = 0;
    bool has_holes = false;

    const ElfW(Phdr)* ph;
    for (ph = phdr; ph < &phdr[l->l_phnum]; ++ph) {
        switch (ph->p_type) {
            /* These entries tell us where to find things once the file's
               segments are mapped in.  We record the addresses it says
               verbatim, and later correct for the run-time load address.  */
            case PT_DYNAMIC:
                l->l_ld    = (void*)ph->p_vaddr;
                l->l_ldnum = ph->p_memsz / sizeof(ElfW(Dyn));
                break;

            case PT_INTERP:
                l->l_interp_libname = (const char*)ph->p_vaddr;
                break;

            case PT_PHDR:
                l->l_phdr = (void*)ph->p_vaddr;
                break;

            case PT_LOAD:
                /* A load command tells us to map in part of the file.
                   We record the load commands and process them all later.  */
                if (!IS_ALLOC_ALIGNED(ph->p_align)) {
                    errstring = "ELF load command alignment not page-aligned";
                    goto call_lose;
                }

                if (!IS_ALIGNED_POW2(ph->p_vaddr - ph->p_offset, ph->p_align)) {
                    errstring = "ELF load command address/offset not properly aligned";
                    goto call_lose;
                }

                if (l->nloadcmds >= MAX_LOADCMDS) {
                    errstring = "too many load commands";
                    goto call_lose;
                }

                c           = &l->loadcmds[l->nloadcmds++];
                c->mapstart = ALLOC_ALIGN_DOWN(ph->p_vaddr);
                c->mapend   = ALLOC_ALIGN_UP(ph->p_vaddr + ph->p_filesz);
                c->dataend  = ph->p_vaddr + ph->p_filesz;
                c->allocend = ph->p_vaddr + ph->p_memsz;
                c->mapoff   = ALLOC_ALIGN_DOWN(ph->p_offset);

                /* Determine whether there is a gap between the last segment
                   and this one.  */
                if (l->nloadcmds > 1 && c[-1].mapend != c->mapstart)
                    has_holes = true;

                /* Optimize a common case.  */
#if (PF_R | PF_W | PF_X) == 7 && (PROT_READ | PROT_WRITE | PROT_EXEC) == 7
                c->prot = (PF_TO_PROT >> ((ph->p_flags & (PF_R | PF_W | PF_X)) * 4)) & 0xf;
#else
                c->prot = 0;
                if (ph->p_flags & PF_R)
                    c->prot |= PROT_READ;
                if (ph->p_flags & PF_W)
                    c->prot |= PROT_WRITE;
                if (ph->p_flags & PF_X)
                    c->prot |= PROT_EXEC;
#endif
                c->flags = MAP_PRIVATE | MAP_FILE;
                break;

            case PT_GNU_RELRO:
                l->l_relro_addr = ph->p_vaddr;
                l->l_relro_size = ph->p_memsz;
                break;
        }
    }

    if (l->nloadcmds == 0) {
        /* This only happens for a bogus object that will be caught with
           another error below.  But we don't want to go through the
           calculations below using NLOADCMDS - 1.  */
        errstring = "object file has no loadable segments";
        goto call_lose;
    }

    c = &l->loadcmds[0];
    /* Length of the sections to be loaded.  */
    maplength = l->loadcmds[l->nloadcmds - 1].allocend - c->mapstart;

    if (e_type == ET_DYN) {
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
        ElfW(Addr) mappref = 0;

        if (type == OBJECT_LOAD) {
            if (addr)
                mappref = (ElfW(Addr))c->mapstart + (ElfW(Addr))addr;
            else
                mappref = (ElfW(Addr))bkeep_unmapped_heap(
                    ALLOC_ALIGN_UP(maplength), c->prot,
                    c->flags | MAP_PRIVATE | (type == OBJECT_INTERNAL ? VMA_INTERNAL : 0), file,
                    c->mapoff, NULL);

            /* Remember which part of the address space this object uses.  */
            ret = (*mmap)(file, (void**)&mappref, ALLOC_ALIGN_UP(maplength), c->prot,
                          c->flags | MAP_PRIVATE, c->mapoff);

            if (ret < 0) {
            map_error:
                errstring = "failed to map segment from shared object";
                goto call_lose;
            }
        } else {
            mappref = (ElfW(Addr))addr;
        }

        l->l_map_start = mappref;
        l->l_map_end   = l->l_map_start + maplength;
        l->l_addr      = l->l_map_start - c->mapstart;

        if (has_holes) {
            /* Change protection on the excess portion to disallow all access;
               the portions we do not remap later will be inaccessible as if
               unallocated.  Then jump into the normal segment-mapping loop to
               handle the portion of the segment past the end of the file
               mapping.  */
            if (type == OBJECT_LOAD)
                DkVirtualMemoryProtect((void*)RELOCATE(l, c->mapend),
                                       l->loadcmds[l->nloadcmds - 1].mapstart - c->mapend,
                                       PAL_PROT_NONE);
            if (type == OBJECT_MAPPED ||
#if BOOKKEEP_INTERNAL_OBJ == 1
                type == OBJECT_INTERNAL ||
#endif
                type == OBJECT_LOAD) {
#if BOOKKEEP_INTERNAL_OBJ == 1
                int flags = (type == OBJECT_INTERNVAL) ? VMA_INTERVAL : 0;
#else
                int flags = 0;
#endif
                bkeep_mprotect((void*)RELOCATE(l, c->mapend),
                               l->loadcmds[l->nloadcmds - 1].mapstart - c->mapend, PROT_NONE,
                               flags);
            }
        }

        goto postmap;
    }

    /* Remember which part of the address space this object uses.  */
    l->l_addr      = 0;
    l->l_map_start = c->mapstart;
    l->l_map_end   = l->l_map_start + maplength;

do_remap:
    while (c < &l->loadcmds[l->nloadcmds]) {
        if (c->mapend > c->mapstart) {
            /* Map the segment contents from the file.  */
            void* mapaddr = (void*)RELOCATE(l, c->mapstart);
            if (type == OBJECT_LOAD || type == OBJECT_REMAP) {
                if ((*mmap)(file, &mapaddr, c->mapend - c->mapstart, c->prot,
                            c->flags | MAP_FIXED | MAP_PRIVATE, c->mapoff) < 0)
                    goto map_error;
            }

#if BOOKKEEP_INTERNAL_OBJ == 0
            if (type != OBJECT_INTERNAL && type != OBJECT_USER && type != OBJECT_VDSO)
#else
            if (type != OBJECT_USER && type != OBJECT_VDSO)
#endif
                bkeep_mmap(mapaddr, c->mapend - c->mapstart, c->prot,
                           c->flags | MAP_FIXED | MAP_PRIVATE |
                               (type == OBJECT_INTERNAL ? VMA_INTERNAL : 0),
                           file, c->mapoff, NULL);
        }

    postmap:
        if (l->l_phdr == 0 && (ElfW(Off))c->mapoff <= header->e_phoff &&
            ((size_t)(c->mapend - c->mapstart + c->mapoff) >=
             header->e_phoff + header->e_phnum * sizeof(ElfW(Phdr))))
            /* Found the program header in this segment.  */
            l->l_phdr = (void*)(c->mapstart + header->e_phoff - c->mapoff);

        if (c->allocend > c->dataend) {
            /* Extra zero pages should appear at the end of this segment,
               after the data mapped from the file.   */
            ElfW(Addr) zero, zeroend, zeropage;

            zero     = (ElfW(Addr))RELOCATE(l, c->dataend);
            zeroend  = ALLOC_ALIGN_UP((ElfW(Addr))RELOCATE(l, c->allocend));
            zeropage = ALLOC_ALIGN_UP(zero);

            if (zeroend < zeropage)
                /* All the extra data is in the last page of the segment.
                   We can just zero it.  */
                zeropage = zeroend;

            if (type != OBJECT_MAPPED && type != OBJECT_INTERNAL && type != OBJECT_USER &&
                type != OBJECT_VDSO && zeropage > zero) {
                /* Zero the final part of the last page of the segment.  */
                if ((c->prot & PROT_WRITE) == 0) {
                    /* Dag nab it.  */
                    if (!DkVirtualMemoryProtect((caddr_t)ALLOC_ALIGN_DOWN(zero), g_pal_alloc_align,
                                                c->prot | PAL_PROT_WRITE)) {
                        errstring = "cannot change memory protections";
                        goto call_lose;
                    }
                    memset((void*)zero, '\0', zeropage - zero);
                    if (!DkVirtualMemoryProtect((caddr_t)ALLOC_ALIGN_DOWN(zero), g_pal_alloc_align,
                                                c->prot)) {
                        errstring = "cannot change memory protections";
                        goto call_lose;
                    }
                } else {
                    memset((void*)zero, '\0', zeropage - zero);
                }
            }

            if (zeroend > zeropage) {
                if (type != OBJECT_MAPPED && type != OBJECT_INTERNAL && type != OBJECT_USER &&
                    type != OBJECT_VDSO) {
                    PAL_PTR mapat =
                        DkVirtualMemoryAlloc((void*)zeropage, zeroend - zeropage, 0, c->prot);
                    if (!mapat) {
                        errstring = "cannot map zero-fill pages";
                        goto call_lose;
                    }
                }

#if BOOKKEEP_INTERNAL_OBJ == 0
                if (type != OBJECT_INTERNAL && type != OBJECT_USER && type != OBJECT_VDSO)
#else
                if (type != OBJECT_USER && type != OBJECT_VDSO)
#endif
                    bkeep_mmap((void*)zeropage, zeroend - zeropage, c->prot,
                               MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED |
                                   (type == OBJECT_INTERNAL ? VMA_INTERNAL : 0),
                               NULL, 0, 0);
            }
        }

        ++c;
    }

    if (type == OBJECT_REMAP)
        goto success;

    if (l->l_ld == 0) {
        if (e_type == ET_DYN) {
            errstring = "object file has no dynamic section";
            goto call_lose;
        }
    } else {
        l->l_real_ld = (ElfW(Dyn)*)RELOCATE(l, l->l_ld);
        l->l_ld      = malloc_copy(l->l_real_ld, sizeof(ElfW(Dyn)) * l->l_ldnum);
    }

    elf_get_dynamic_info(l);

    /* When we profile the SONAME might be needed for something else but
       loading.  Add it right away.  */
    if (l->l_info[DT_STRTAB] && l->l_info[DT_SONAME]) {
        /* DEP 3/12/18: This string is not stable; copy it. */
        char* tmp   = (char*)(D_PTR(l->l_info[DT_STRTAB]) + D_PTR(l->l_info[DT_SONAME]));
        l->l_soname = malloc_copy(tmp, strlen(tmp) + 1);
    }

    if (l->l_phdr == NULL) {
        /* The program header is not contained in any of the segments.
           We have to allocate memory ourself and copy it over from out
           temporary place.  */
        ElfW(Phdr)* newp = (ElfW(Phdr)*)malloc(header->e_phnum * sizeof(ElfW(Phdr)));
        if (newp == NULL) {
            errstring = "cannot allocate memory for program header";
            goto call_lose;
        }

        l->l_phdr = memcpy(newp, phdr, (header->e_phnum * sizeof(ElfW(Phdr))));
    } else {
        /* Adjust the PT_PHDR value by the runtime load address.  */
        l->l_phdr = (ElfW(Phdr)*)RELOCATE(l, l->l_phdr);
    }

    l->l_entry = RELOCATE(l, l->l_entry);

    /* Set up the symbol hash table.  */
    setup_elf_hash(l);

success:
    free(new_phdr);
    return l;

call_lose:
    free(new_phdr);
    debug("loading %s: %s\n", l->l_name, errstring);
    if (l != remap) {
        /* l was allocated via new_elf_object() */
        free(l);
    }
    return NULL;
}

static inline struct link_map* __search_map_by_name(const char* name) {
    struct link_map* l = loaded_libraries;
    int len            = strlen(name);

    while (l) {
        if (l->l_name && !memcmp(l->l_name, name, len + 1))
            break;
        l = l->l_next;
    }

    return l;
}

static inline struct link_map* __search_map_by_handle(struct shim_handle* file) {
    struct link_map* l = loaded_libraries;

    while (l) {
        if (l->l_file == file)
            break;
        l = l->l_next;
    }

    return l;
}

static inline struct link_map* __search_map_by_addr(void* addr) {
    struct link_map* l = loaded_libraries;

    while (l) {
        if ((void*)l->l_map_start == addr)
            break;
        l = l->l_next;
    }

    return l;
}

static int __remove_elf_object(struct link_map* l) {
    if (l->l_prev)
        l->l_prev->l_next = l->l_next;
    if (l->l_next)
        l->l_next->l_prev = l->l_prev;

    remove_r_debug((void*)l->l_addr);

    if (loaded_libraries == l)
        loaded_libraries = l->l_next;

    if (interp_map == l)
        interp_map = NULL;

    free(l);

    return 0;
}

static int __free_elf_object(struct link_map* l) {
    debug("removing %s as runtime object loaded at 0x%08lx\n", l->l_name, l->l_map_start);

    struct loadcmd* c = l->loadcmds;

    while (c < &l->loadcmds[l->nloadcmds]) {
        if (c->mapend > c->mapstart)
            /* Unmap the segment contents from the file.  */
            shim_do_munmap((void*)l->l_addr + c->mapstart, c->mapend - c->mapstart);

        if (c->allocend > c->dataend) {
            /* Extra zero pages should appear at the end of this segment,
               after the data mapped from the file.   */
            ElfW(Addr) zero, zeroend, zeropage;

            zero     = l->l_addr + c->dataend;
            zeroend  = l->l_addr + c->allocend;
            zeropage = ALLOC_ALIGN_UP(zero);

            if (zeroend < zeropage)
                /* All the extra data is in the last page of the segment.
                   We can just zero it.  */
                zeropage = zeroend;

            if (zeroend > zeropage)
                shim_do_munmap((void*)zeropage, zeroend - zeropage);
        }

        ++c;
    }

    __remove_elf_object(l);

    return 0;
}

int free_elf_object(struct shim_handle* file) {
    struct link_map* l = __search_map_by_handle(file);
    if (!l)
        return -ENOENT;

    __free_elf_object(l);
    put_handle(file);
    return 0;
}

static int __check_elf_header(void* fbp, size_t len) {
    const char* errstring __attribute__((unused));

    /* Now we will start verify the file as a ELF header. This part of code
       is borrow from open_verify() */
    ElfW(Ehdr)* ehdr = (ElfW(Ehdr)*)fbp;

    if (len < sizeof(ElfW(Ehdr))) {
        errstring = "ELF file with a strange size";
        goto verify_failed;
    }

#define ELF32_CLASS ELFCLASS32
#define ELF64_CLASS ELFCLASS64

    static const unsigned char expected[EI_NIDENT] = {
        [EI_MAG0] = ELFMAG0,       [EI_MAG1] = ELFMAG1,      [EI_MAG2] = ELFMAG2,
        [EI_MAG3] = ELFMAG3,       [EI_CLASS] = ELFW(CLASS), [EI_DATA] = byteorder,
        [EI_VERSION] = EV_CURRENT, [EI_OSABI] = 0,
    };

    /* See whether the ELF header is what we expect.  */
    if (memcmp(ehdr->e_ident, expected, EI_OSABI) != 0 ||
            (ehdr->e_ident[EI_OSABI] != ELFOSABI_SYSV &&
             ehdr->e_ident[EI_OSABI] != ELFOSABI_LINUX)) {
        errstring = "ELF file with invalid header";
        goto verify_failed;
    }

    if (memcmp(&ehdr->e_ident[EI_PAD], &expected[EI_PAD], EI_NIDENT - EI_PAD) != 0) {
        errstring = "nonzero padding in e_ident";
        goto verify_failed;
    }

    /* Now we check if the host match the elf machine profile */
    if (!elf_machine_matches_host(ehdr)) {
        errstring = "ELF file does not match with the host";
        goto verify_failed;
    }

    /* check if the type of ELF header is either DYN or EXEC */
    if (ehdr->e_type != ET_DYN && ehdr->e_type != ET_EXEC) {
        errstring = "only ET_DYN and ET_EXEC can be loaded\n";
        goto verify_failed;
    }

    /* check if phentsize match the size of ElfW(Phdr) */
    if (ehdr->e_phentsize != sizeof(ElfW(Phdr))) {
        errstring = "ELF file's phentsize not the expected size";
        goto verify_failed;
    }

    return 0;

verify_failed:
    debug("load runtime object: %s\n", errstring);
    return -EINVAL;
}

static int __read_elf_header(struct shim_handle* file, void* fbp) {
    if (!file)
        return -EINVAL;

    if (!file->fs || !file->fs->fs_ops)
        return -EACCES;

    ssize_t (*read)(struct shim_handle*, void*, size_t) = file->fs->fs_ops->read;
    off_t (*seek)(struct shim_handle*, off_t, int)      = file->fs->fs_ops->seek;

    if (!read || !seek)
        return -EACCES;

    (*seek)(file, 0, SEEK_SET);
    int ret = (*read)(file, fbp, FILEBUF_SIZE);
    (*seek)(file, 0, SEEK_SET);
    return ret;
}

static int __load_elf_header(struct shim_handle* file, void* fbp, int* plen) {
    int len = __read_elf_header(file, fbp);
    if (len < 0)
        return len;

    int ret = __check_elf_header(fbp, len);
    if (ret < 0)
        return ret;

    if (plen)
        *plen = len;

    return 0;
}

int check_elf_object(struct shim_handle* file) {
    char fb[FILEBUF_SIZE];

    int l = __read_elf_header(file, &fb);
    if (l < 0)
        return l;

    return __check_elf_header(&fb, l);
}

static int __load_elf_object(struct shim_handle* file, void* addr, int type,
                             struct link_map* remap);

int load_elf_object(struct shim_handle* file, void* addr, size_t mapped) {
    if (!file)
        return -EINVAL;

    if (mapped)
        debug("adding %s as runtime object loaded at %p-%p\n",
              file ? qstrgetstr(&file->uri) : "(unknown)", addr, addr + mapped);
    else
        debug("loading %s as runtime object at %p\n", file ? qstrgetstr(&file->uri) : "(unknown)",
              addr);

    return __load_elf_object(file, addr, mapped ? OBJECT_MAPPED : OBJECT_LOAD, NULL);
}

static void add_link_map(struct link_map* map) {
    struct link_map* prev   = NULL;
    struct link_map** pprev = &loaded_libraries;
    struct link_map* next   = loaded_libraries;

    while (next) {
        prev  = next;
        pprev = &next->l_next;
        next  = next->l_next;
    }

    *pprev      = map;
    map->l_prev = prev;
    map->l_next = NULL;
}

static void replace_link_map(struct link_map* new, struct link_map* old) {
    new->l_next = old->l_next;
    new->l_prev = old->l_prev;

    if (old->l_next)
        old->l_next->l_prev = new;
    if (old->l_prev)
        old->l_prev->l_next = new;

    if (loaded_libraries == old)
        loaded_libraries = new;
}

static int do_relocate_object(struct link_map* l);

static int __load_elf_object(struct shim_handle* file, void* addr, int type,
                             struct link_map* remap) {
    char* hdr = addr;
    int len = 0, ret = 0;

    if (type == OBJECT_LOAD || type == OBJECT_REMAP) {
        hdr = __alloca(FILEBUF_SIZE);
        if ((ret = __load_elf_header(file, hdr, &len)) < 0)
            goto out;
    }

    struct link_map* map = __map_elf_object(file, hdr, len, addr, type, remap);

    if (!map) {
        ret = -EINVAL;
        goto out;
    }

    if (type != OBJECT_INTERNAL && type != OBJECT_VDSO)
        do_relocate_object(map);

    if (internal_map) {
        map->l_resolved     = true;
        map->l_resolved_map = internal_map->l_addr;
    }

    if (type == OBJECT_INTERNAL)
        internal_map = map;
    if (type == OBJECT_VDSO)
        vdso_map = map;

    if (type != OBJECT_REMAP) {
        if (file) {
            get_handle(file);
            map->l_file = file;
        }

        add_link_map(map);
    }

    if ((type == OBJECT_LOAD || type == OBJECT_REMAP || type == OBJECT_USER) && map->l_file &&
        !qstrempty(&map->l_file->uri)) {
        if (type == OBJECT_REMAP)
            remove_r_debug((void*)map->l_addr);

        append_r_debug(qstrgetstr(&map->l_file->uri), (void*)map->l_map_start,
                       (void*)map->l_real_ld);
    }

out:
    return ret;
}

int reload_elf_object(struct shim_handle* file) {
    struct link_map* map = loaded_libraries;

    while (map) {
        if (map->l_file == file)
            break;
        map = map->l_next;
    }

    if (!map)
        return -ENOENT;

    debug("reloading %s as runtime object loaded at 0x%08lx-0x%08lx\n", qstrgetstr(&file->uri),
          map->l_map_start, map->l_map_end);

    return __load_elf_object(file, NULL, OBJECT_REMAP, map);
}

struct sym_val {
    ElfW(Sym)* s;
    struct link_map* m;
};

static uint_fast32_t elf_fast_hash(const char* s) {
    uint_fast32_t h = 5381;
    for (unsigned char c = *s; c != '\0'; c = *++s) {
        h = h * 33 + c;
    }
    return h & 0xffffffff;
}

/* This is the hashing function specified by the ELF ABI.  In the
   first five operations no overflow is possible so we optimized it a
   bit.  */
static unsigned long int elf_hash(const char* name_arg) {
    const unsigned char* name = (const unsigned char*)name_arg;
    unsigned long int hash    = 0;

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
        hi   = hash & 0xf0000000;

        /* The algorithm specified in the ELF ABI is as follows:
               if (hi != 0)
                   hash ^= hi >> 24;

               hash &= ~hi;
           But the following is equivalent and a lot faster, especially on
           modern processors.  */

        hash ^= hi;
        hash ^= hi >> 24;
    }
    return hash;
}

static ElfW(Sym)* do_lookup_map(ElfW(Sym)* ref, const char* undef_name, const uint_fast32_t hash,
                                unsigned long int elf_hash, const struct link_map* map) {
    /* These variables are used in the nested function.  */
    Elf_Symndx symidx;
    ElfW(Sym)* sym;
    /* The tables for this map.  */
    ElfW(Sym)* symtab  = (void*)D_PTR(map->l_info[DT_SYMTAB]);
    const char* strtab = (const void*)D_PTR(map->l_info[DT_STRTAB]);
    int len            = strlen(undef_name);

    /* Nested routine to check whether the symbol matches.  */
    ElfW(Sym)* check_match(ElfW(Sym)* sym) {
        unsigned int stt = ELFW(ST_TYPE)(sym->st_info);

        if ((sym->st_value == 0 /* No value */ && stt != STT_TLS) || sym->st_shndx == SHN_UNDEF)
            return NULL;

/* Ignore all but STT_NOTYPE, STT_OBJECT, STT_FUNC,
   STT_COMMON, STT_TLS, and STT_GNU_IFUNC since these are no
   code/data definitions.  */
#define ALLOWED_STT                                                                \
    ((1 << STT_NOTYPE) | (1 << STT_OBJECT) | (1 << STT_FUNC) | (1 << STT_COMMON) | \
     (1 << STT_TLS) | (1 << STT_GNU_IFUNC))

        if (((1 << stt) & ALLOWED_STT) == 0)
            return NULL;

        if (sym != ref && memcmp(strtab + sym->st_name, undef_name, len + 1))
            /* Not the symbol we are looking for.  */
            return NULL;

        /* There cannot be another entry for this symbol so stop here.  */
        return sym;
    }

    const ElfW(Addr)* bitmask = map->l_gnu_bitmask;

    if (bitmask != NULL) {
        ElfW(Addr) bitmask_word = bitmask[(hash / __ELF_NATIVE_CLASS) & map->l_gnu_bitmask_idxbits];

        unsigned int hashbit1 = hash & (__ELF_NATIVE_CLASS - 1);
        unsigned int hashbit2 = (hash >> map->l_gnu_shift) & (__ELF_NATIVE_CLASS - 1);

        if ((bitmask_word >> hashbit1) & (bitmask_word >> hashbit2) & 1) {
            Elf32_Word bucket = map->l_gnu_buckets[hash % map->l_nbuckets];

            if (bucket != 0) {
                const Elf32_Word* hasharr = &map->l_gnu_chain_zero[bucket];

                do {
                    if (((*hasharr ^ hash) >> 1) == 0) {
                        symidx = hasharr - map->l_gnu_chain_zero;
                        sym    = check_match(&symtab[symidx]);
                        if (sym != NULL)
                            return sym;
                    }
                } while ((*hasharr++ & 1u) == 0);
            }
        }

        /* No symbol found.  */
        symidx = SHN_UNDEF;
    } else {
        /* Use the old SysV-style hash table.  Search the appropriate
           hash bucket in this object's symbol table for a definition
           for the same symbol name.  */
        for (symidx = map->l_buckets[elf_hash % map->l_nbuckets]; symidx != STN_UNDEF;
             symidx = map->l_chain[symidx]) {
            sym = check_match(&symtab[symidx]);
            if (sym != NULL)
                return sym;
        }
    }

    return NULL;
}

/* Inner part of the lookup functions.  We return a value > 0 if we
   found the symbol, the value 0 if nothing is found and < 0 if
   something bad happened.  */
static ElfW(Sym)* __do_lookup(const char* undef_name, ElfW(Sym)* ref, struct link_map* map) {
    const uint_fast32_t fast_hash = elf_fast_hash(undef_name);
    const long int hash           = elf_hash(undef_name);
    return do_lookup_map(ref, undef_name, fast_hash, hash, map);
}

static int do_lookup(const char* undef_name, ElfW(Sym)* ref, struct sym_val* result) {
    ElfW(Sym)* sym = NULL;

    sym = __do_lookup(undef_name, ref, internal_map);

    if (!sym)
        return 0;

    switch (ELFW(ST_BIND)(sym->st_info)) {
        case STB_WEAK:
            /* Weak definition.  Use this value if we don't find another. */
            if (!result->s) {
                result->s = sym;
                result->m = (struct link_map*)internal_map;
            }
            break;

            /* FALLTHROUGH */
        case STB_GLOBAL:
        case STB_GNU_UNIQUE:
            /* success: */
            /* Global definition.  Just what we need.  */
            result->s = sym;
            result->m = (struct link_map*)internal_map;
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
struct link_map* lookup_symbol(const char* undef_name, ElfW(Sym)** ref) {
    struct sym_val current_value = {NULL, NULL};

    do_lookup(undef_name, *ref, &current_value);

    if (current_value.s == NULL) {
        *ref = NULL;
        return NULL;
    }

    *ref = current_value.s;
    return current_value.m;
}

static int do_relocate_object(struct link_map* l) {
    int ret = 0;

    if (l->l_resolved)
        ELF_REDO_DYNAMIC_RELOCATE(l);
    else
        ELF_DYNAMIC_RELOCATE(l);

    if ((ret = reprotect_map(l)) < 0)
        return ret;

    return 0;
}

static bool __need_interp(struct link_map* exec_map) {
    if (!exec_map->l_interp_libname)
        return false;

    const char* strtab = (const void*)D_PTR(exec_map->l_info[DT_STRTAB]);
    const ElfW(Dyn)* d;

    for (d = exec_map->l_ld; d->d_tag != DT_NULL; d++)
        if (d->d_tag == DT_NEEDED) {
            const char* name     = strtab + d->d_un.d_val;
            int len              = strlen(name);
            const char* filename = name + len - 1;
            while (filename > name && *filename != '/') {
                filename--;
            }
            if (*filename == '/')
                filename++;

            /* if we find a dependency besides libsysdb.so, the
               interpreter is necessary */
            if (memcmp(filename, "libsysdb", 8))
                return true;
        }

    return false;
}

extern const char** library_paths;

int free_elf_interp(void) {
    if (interp_map)
        __free_elf_object(interp_map);

    return 0;
}

static int __load_interp_object(struct link_map* exec_map) {
    const char* interp_name = (const char*)exec_map->l_interp_libname + (long)exec_map->l_addr;
    int len                 = strlen(interp_name);
    const char* filename    = interp_name + len - 1;
    while (filename > interp_name && *filename != '/') {
        filename--;
    }
    if (*filename == '/')
        filename++;
    len -= filename - interp_name;

    const char* default_paths[] = {"/lib", "/lib64", NULL};
    const char** paths          = library_paths ?: default_paths;
    char interp_path[STR_SIZE];

    for (const char** p = paths; *p; p++) {
        int plen = strlen(*p);
        memcpy(interp_path, *p, plen);
        interp_path[plen] = '/';
        memcpy(interp_path + plen + 1, filename, len + 1);

        debug("search interpreter: %s\n", interp_path);

        struct shim_dentry* dent = NULL;
        int ret                  = 0;

        if ((ret = path_lookupat(NULL, interp_path, LOOKUP_OPEN, &dent, NULL)) < 0 ||
            dent->state & DENTRY_NEGATIVE)
            continue;

        struct shim_mount* fs = dent->fs;
        get_dentry(dent);

        if (!fs->d_ops->open) {
            ret = -EACCES;
        err:
            put_dentry(dent);
            return ret;
        }

        if (fs->d_ops->mode) {
            mode_t mode;
            if ((ret = fs->d_ops->mode(dent, &mode)) < 0)
                goto err;
        }

        struct shim_handle* interp = NULL;

        if (!(interp = get_new_handle())) {
            ret = -ENOMEM;
            goto err;
        }

        set_handle_fs(interp, fs);
        interp->flags    = O_RDONLY;
        interp->acc_mode = MAY_READ;

        if ((ret = fs->d_ops->open(interp, dent, O_RDONLY)) < 0) {
            put_handle(interp);
            goto err;
        }

        if (!(ret = __load_elf_object(interp, NULL, OBJECT_LOAD, NULL)))
            interp_map = __search_map_by_handle(interp);

        put_handle(interp);
        return ret;
    }

    return -ENOENT;
}

int load_elf_interp(struct shim_handle* exec) {
    struct link_map* exec_map = __search_map_by_handle(exec);

    if (exec_map && !interp_map && __need_interp(exec_map))
        __load_interp_object(exec_map);

    return 0;
}

int remove_loaded_libraries(void) {
    struct link_map* map = loaded_libraries;
    struct link_map* next_map = map->l_next;
    while (map) {
        if (map->l_type != OBJECT_INTERNAL && map->l_type != OBJECT_VDSO)
            __remove_elf_object(map);

        map      = next_map;
        next_map = map ? map->l_next : NULL;
    }

    return 0;
}

/*
 * libsysdb.so is loaded as shared library and load address for child may not match the one for
 * parent. Just treat vdso page as user-program data and adjust function pointers for vdso
 * functions after migration.
 */
static void* vdso_addr __attribute_migratable                       = NULL;
static ElfW(Addr)* __vdso_shim_clock_gettime __attribute_migratable = NULL;
static ElfW(Addr)* __vdso_shim_gettimeofday __attribute_migratable  = NULL;
static ElfW(Addr)* __vdso_shim_time __attribute_migratable          = NULL;
static ElfW(Addr)* __vdso_shim_getcpu __attribute_migratable        = NULL;

static const struct {
    const char* name;
    ElfW(Addr) value;
    ElfW(Addr)** func;
} vsyms[] = {{
                 .name  = "__vdso_shim_clock_gettime",
                 .value = (ElfW(Addr))&__shim_clock_gettime,
                 .func  = &__vdso_shim_clock_gettime,
             },
             {
                 .name  = "__vdso_shim_gettimeofday",
                 .value = (ElfW(Addr))&__shim_gettimeofday,
                 .func  = &__vdso_shim_gettimeofday,
             },
             {
                 .name  = "__vdso_shim_time",
                 .value = (ElfW(Addr))&__shim_time,
                 .func  = &__vdso_shim_time,
             },
             {
                 .name  = "__vdso_shim_getcpu",
                 .value = (ElfW(Addr))&__shim_getcpu,
                 .func  = &__vdso_shim_getcpu,
             }};

static int vdso_map_init(void) {
    /*
     * Allocate vdso page as user program allocated it.
     * Using directly vdso code in LibOS causes trouble when emulating fork.
     * In host child process, LibOS may or may not be loaded at the same address.
     * When LibOS is loaded at different address, it may overlap with the old vDSO
     * area.
     */
    void* addr = bkeep_unmapped_heap(ALLOC_ALIGN_UP(vdso_so_size), PROT_READ | PROT_EXEC, 0, NULL, 0,
                                     "linux-vdso.so.1");
    if (addr == NULL)
        return -ENOMEM;
    assert(addr == ALLOC_ALIGN_UP_PTR(addr));

    void* ret_addr = (void*)DkVirtualMemoryAlloc(addr, ALLOC_ALIGN_UP(vdso_so_size), 0,
                                                 PAL_PROT_READ | PAL_PROT_WRITE);
    if (!ret_addr)
        return -PAL_ERRNO;
    assert(addr == ret_addr);

    memcpy(addr, &vdso_so, vdso_so_size);
    memset(addr + vdso_so_size, 0, ALLOC_ALIGN_UP(vdso_so_size) - vdso_so_size);
    __load_elf_object(NULL, addr, OBJECT_VDSO, NULL);
    vdso_map->l_name = "vDSO";

    for (size_t i = 0; i < ARRAY_SIZE(vsyms); i++) {
        ElfW(Sym)* sym = __do_lookup(vsyms[i].name, NULL, vdso_map);
        if (sym == NULL) {
            debug("vDSO: symbol value for %s not found\n", vsyms[i].name);
            continue;
        }
        *vsyms[i].func  = (ElfW(Addr)*)(vdso_map->l_addr + sym->st_value);
        **vsyms[i].func = vsyms[i].value;
    }

    if (!DkVirtualMemoryProtect(addr, ALLOC_ALIGN_UP(vdso_so_size), PAL_PROT_READ | PAL_PROT_EXEC))
        return -PAL_ERRNO;

    vdso_addr = addr;
    return 0;
}

int vdso_map_migrate(void) {
    if (!vdso_addr)
        return 0;

    if (!DkVirtualMemoryProtect(vdso_addr, ALLOC_ALIGN_UP(vdso_so_size),
                                PAL_PROT_READ | PAL_PROT_WRITE))
        return -PAL_ERRNO;

    /* adjust funcs to loaded address for newly loaded libsysdb */
    for (size_t i = 0; i < ARRAY_SIZE(vsyms); i++) {
        **vsyms[i].func = vsyms[i].value;
    }

    if (!DkVirtualMemoryProtect(vdso_addr, ALLOC_ALIGN_UP(vdso_so_size),
                                PAL_PROT_READ | PAL_PROT_EXEC))
        return -PAL_ERRNO;
    return 0;
}

int init_internal_map(void) {
    __load_elf_object(NULL, &__load_address, OBJECT_INTERNAL, NULL);
    internal_map->l_name = "libsysdb.so";
    return 0;
}

int init_loader(void) {
    struct shim_thread* cur_thread = get_cur_thread();
    int ret                        = 0;

    lock(&cur_thread->lock);
    struct shim_handle* exec = cur_thread->exec;
    if (exec)
        get_handle(exec);
    unlock(&cur_thread->lock);

    if (!exec)
        return 0;

    struct link_map* exec_map = __search_map_by_handle(exec);

    if (!exec_map) {
        if ((ret = load_elf_object(exec, (void*)PAL_CB(executable_range.start),
                                   PAL_CB(executable_range.end) - PAL_CB(executable_range.start))) <
            0)
            goto out;

        exec_map = __search_map_by_handle(exec);
    }

    ret = init_brk_from_executable(exec);
    if (ret < 0)
        goto out;

    if (!interp_map && __need_interp(exec_map) && (ret = __load_interp_object(exec_map)) < 0)
        goto out;

    ret = 0;
out:
    put_handle(exec);
    return ret;
}

int init_brk_from_executable(struct shim_handle* exec) {
    struct link_map* exec_map = __search_map_by_handle(exec);
    if (exec_map) {
        size_t data_segment_size = 0;
        // Count all the data segments (including BSS)
        struct loadcmd* c = exec_map->loadcmds;
        for (; c < &exec_map->loadcmds[exec_map->nloadcmds]; c++)
            if (!(c->prot & PROT_EXEC))
                data_segment_size += c->allocend - c->mapstart;

        return init_brk_region((void*)ALLOC_ALIGN_UP(exec_map->l_map_end), data_segment_size);
    }
    return 0;
}

int register_library(const char* name, unsigned long load_address) {
    debug("glibc register library %s loaded at 0x%08lx\n", name, load_address);

    struct shim_handle* hdl = get_new_handle();

    if (!hdl)
        return -ENOMEM;

    int err = open_namei(hdl, NULL, name, O_RDONLY, 0, NULL);
    if (err < 0) {
        put_handle(hdl);
        return err;
    }

    __load_elf_object(hdl, (void*)load_address, OBJECT_USER, NULL);
    put_handle(hdl);
    return 0;
}

noreturn void execute_elf_object(struct shim_handle* exec, int* argcp, const char** argp,
                                 ElfW(auxv_t)* auxp) {
    __UNUSED(argp);
    int ret = vdso_map_init();
    if (ret < 0) {
        SYS_PRINTF("Could not initialize vDSO (error code = %d)", ret);
        shim_clean_and_exit(ret);
    }

    struct link_map* exec_map = __search_map_by_handle(exec);
    assert(exec_map);
    assert(IS_ALIGNED_PTR(argcp, 16)); /* stack must be 16B-aligned */
    assert((void*)argcp + sizeof(long) == argp || argp == NULL);

    static_assert(REQUIRED_ELF_AUXV >= 8, "not enough space on stack for auxv");
    auxp[0].a_type     = AT_PHDR;
    auxp[0].a_un.a_val = (__typeof(auxp[0].a_un.a_val))exec_map->l_phdr;
    auxp[1].a_type     = AT_PHNUM;
    auxp[1].a_un.a_val = exec_map->l_phnum;
    auxp[2].a_type     = AT_PAGESZ;
    auxp[2].a_un.a_val = g_pal_alloc_align;
    auxp[3].a_type     = AT_ENTRY;
    auxp[3].a_un.a_val = exec_map->l_entry;
    auxp[4].a_type     = AT_BASE;
    auxp[4].a_un.a_val = interp_map ? interp_map->l_addr : 0;
    auxp[5].a_type     = AT_RANDOM;
    auxp[5].a_un.a_val = 0; /* filled later */
    if (vdso_addr) {
        auxp[6].a_type     = AT_SYSINFO_EHDR;
        auxp[6].a_un.a_val = (uint64_t)vdso_addr;
    } else {
        auxp[6].a_type     = AT_NULL;
        auxp[6].a_un.a_val = 0;
    }
    auxp[7].a_type     = AT_NULL;
    auxp[7].a_un.a_val = 0;

    /* populate extra memory space for aux vector data */
    static_assert(REQUIRED_ELF_AUXV_SPACE >= 16, "not enough space on stack for auxv");
    ElfW(Addr) auxp_extra = (ElfW(Addr))&auxp[8];

    ElfW(Addr) random = auxp_extra; /* random 16B for AT_RANDOM */
    ret               = DkRandomBitsRead((PAL_PTR)random, 16);
    if (ret < 0) {
        debug("execute_elf_object: DkRandomBitsRead failed.\n");
        DkThreadExit(/*clear_child_tid=*/NULL);
    }
    auxp[5].a_un.a_val = random;

    ElfW(Addr) entry = interp_map ? interp_map->l_entry : exec_map->l_entry;

    /* Ready to start execution, re-enable preemption. */
    shim_tcb_t* tcb = shim_get_tcb();
    __enable_preempt(tcb);

#if defined(__x86_64__)
    __asm__ volatile(
        "pushq $0\r\n"
        "popfq\r\n"
        "movq %%rbx, %%rsp\r\n"
        "jmp *%%rax\r\n"
        :
        : "a"(entry), "b"(argcp), "d"(0)
        : "memory", "cc");
#else
#error "architecture not supported"
#endif
    while (true)
        /* nothing */;
}

BEGIN_CP_FUNC(library) {
    __UNUSED(size);
    assert(size == sizeof(struct link_map));

    struct link_map* map = (struct link_map*)obj;
    struct link_map* new_map;

    ptr_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off = ADD_CP_OFFSET(sizeof(struct link_map));
        ADD_TO_CP_MAP(obj, off);

        new_map = (struct link_map*)(base + off);
        memcpy(new_map, map, sizeof(struct link_map));

        new_map->l_prev   = NULL;
        new_map->l_next   = NULL;
        new_map->textrels = NULL;

        if (map->l_file)
            DO_CP_MEMBER(handle, map, new_map, l_file);

        if (map->l_ld) {
            size_t size   = sizeof(ElfW(Dyn)) * map->l_ldnum;
            ElfW(Dyn)* ld = (void*)(base + ADD_CP_OFFSET(size));
            memcpy(ld, map->l_ld, size);
            new_map->l_ld = ld;

            ElfW(Dyn)** start = new_map->l_info;
            ElfW(Dyn)** end   = (void*)start + sizeof(new_map->l_info);
            ElfW(Dyn)** dyn;
            for (dyn = start; dyn < end; dyn++)
                if (*dyn)
                    *dyn = (void*)*dyn + ((void*)ld - (void*)map->l_ld);
        }

        if (map->l_name) {
            size_t namelen = strlen(map->l_name);
            char* name     = (char*)(base + ADD_CP_OFFSET(namelen + 1));
            memcpy(name, map->l_name, namelen + 1);
            new_map->l_name = name;
        }

        if (map->l_soname) {
            size_t sonamelen = strlen(map->l_soname);
            char* soname     = (char*)(base + ADD_CP_OFFSET(sonamelen + 1));
            memcpy(soname, map->l_soname, sonamelen + 1);
            new_map->l_soname = soname;
        }

        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_map = (struct link_map*)(base + off);
    }

    if (objp)
        *objp = (void*)new_map;
}
END_CP_FUNC(library)

DEFINE_PROFILE_CATEGORY(inside_rs_library, resume_func);
DEFINE_PROFILE_INTERVAL(clean_up_library, inside_rs_library);
DEFINE_PROFILE_INTERVAL(search_library_vma, inside_rs_library);
DEFINE_PROFILE_INTERVAL(relocate_library, inside_rs_library);
DEFINE_PROFILE_INTERVAL(add_or_replace_library, inside_rs_library);

BEGIN_RS_FUNC(library) {
    __UNUSED(offset);
    struct link_map* map = (void*)(base + GET_CP_FUNC_ENTRY());

    CP_REBASE(map->l_name);
    CP_REBASE(map->l_soname);
    CP_REBASE(map->l_file);

    if (map->l_ld && map->l_ld != map->l_real_ld) {
        CP_REBASE(map->l_ld);
        CP_REBASE(map->l_info);
    }

    BEGIN_PROFILE_INTERVAL();

    struct link_map* old_map = __search_map_by_name(map->l_name);

    if (old_map)
        remove_r_debug((void*)old_map->l_addr);

    SAVE_PROFILE_INTERVAL(clean_up_library);

    if (internal_map && (!map->l_resolved || map->l_resolved_map != internal_map->l_addr)) {
        do_relocate_object(map);
        SAVE_PROFILE_INTERVAL(relocate_library);
    }

    if (old_map)
        replace_link_map(map, old_map);
    else
        add_link_map(map);

    SAVE_PROFILE_INTERVAL(add_or_replace_library);

    DEBUG_RS("base=0x%08lx,name=%s", map->l_addr, map->l_name);
}
END_RS_FUNC(library)

BEGIN_CP_FUNC(loaded_libraries) {
    __UNUSED(obj);
    __UNUSED(size);
    __UNUSED(objp);
    struct link_map* map = loaded_libraries;
    struct link_map* new_interp_map = NULL;
    while (map) {
        struct link_map* new_map = NULL;

        if (map != internal_map)
            DO_CP(library, map, &new_map);

        if (map == interp_map)
            new_interp_map = new_map;

        map = map->l_next;
    }

    ADD_CP_FUNC_ENTRY((ptr_t)new_interp_map);
}
END_CP_FUNC(loaded_libraries)

BEGIN_RS_FUNC(loaded_libraries) {
    __UNUSED(base);
    __UNUSED(offset);
    interp_map = (void*)GET_CP_FUNC_ENTRY();

    if (interp_map) {
        CP_REBASE(interp_map);
        DEBUG_RS("%s as interp", interp_map->l_name);
    }
}
END_RS_FUNC(loaded_libraries)
