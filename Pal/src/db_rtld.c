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

#include <sysdeps/generic/ldsodefs.h>
#include <elf/elf.h>

struct link_map * loaded_maps = NULL;
struct link_map * exec_map = NULL;

struct link_map * lookup_symbol (const char *undef_name, ElfW(Sym) **ref);

/* This macro is used as a callback from the ELF_DYNAMIC_RELOCATE code.  */
static struct link_map * resolve_map (const char **strtab, ElfW(Sym) ** ref)
{
    if (ELFW(ST_BIND) ((*ref)->st_info) != STB_LOCAL) {
        struct link_map * l = lookup_symbol((*strtab) + (*ref)->st_name, ref);
        if (l) {
            *strtab = (const void *) D_PTR (l->l_info[DT_STRTAB]);
            return l;
        }
    }
    return 0;
}

/* Define RESOLVE_RTLD as 0 since we rely on resolve_map on
 * all current PAL platforms */
#define RESOLVE_RTLD(sym_name)      0
#define RESOLVE_MAP(strtab, ref)    resolve_map(strtab, ref)

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
                  malloc_copy(realname, strlen(realname) + 1) :
                  NULL;
    new->l_type = type;
    return new;
}

/* Cache the location of MAP's hash table.  */
void setup_elf_hash (struct link_map *map)
{
    Elf_Symndx * hash;

    if (map->l_info[DT_ADDRTAGIDX(DT_GNU_HASH) + DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM
                    + DT_EXTRANUM + DT_VALNUM] != NULL) {
        Elf32_Word *hash32
            = (void *) D_PTR (map->l_info[DT_ADDRTAGIDX (DT_GNU_HASH) + DT_NUM
                        + DT_THISPROCNUM + DT_VERSIONTAGNUM
                        + DT_EXTRANUM + DT_VALNUM]);

        map->l_nbuckets = *hash32++;

        Elf32_Word symbias = *hash32++;
        Elf32_Word bitmask_nwords = *hash32++;

        assert(IS_POWER_OF_2(bitmask_nwords));
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

/* Map in the shared object NAME, actually located in REALNAME, and already
   opened on FD */
struct link_map *
map_elf_object_by_handle (PAL_HANDLE handle, enum object_type type,
                          void * fbp, size_t fbp_len,
                          bool do_copy_dyn)
{
    struct link_map * l = new_elf_object(_DkStreamRealpath(handle), type);
    int ret;

    if (handle == NULL) {
        print_error("cannot stat shared object", -PAL_ERROR_INVAL);
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

    if (header->e_phoff + maplength <= fbp_len) {
        phdr = (void *) ((char *) fbp + header->e_phoff);
    } else {
        phdr = (ElfW(Phdr) *) malloc (maplength);

        if ((ret = _DkStreamRead(handle, header->e_phoff, maplength, phdr,
                                 NULL, 0)) < 0) {
            print_error("cannot read file data", ret);
            return NULL;
        }
    }

    /* Presumed absent PT_GNU_STACK.  */
    //uint_fast16_t stack_flags = PF_R|PF_W|PF_X;

    /* Scan the program header table, collecting its load commands.  */
    struct loadcmd {
        ElfW(Addr) mapstart, mapend, dataend, allocend;
        unsigned int mapoff;
        int prot;
    } * loadcmds, *c;
    loadcmds = __alloca(sizeof(struct loadcmd) * l->l_phnum);

    int nloadcmds = 0;
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
                if (!IS_ALLOC_ALIGNED(ph->p_align)) {
                    print_error("ELF load command alignment not aligned",
                                -PAL_ERROR_NOMEM);
                    return NULL;
                }

                if (!IS_ALIGNED_POW2(ph->p_vaddr - ph->p_offset, ph->p_align)) {
                    print_error("ELF load command address/offset not properly aligned",
                                -PAL_ERROR_NOMEM);
                    return NULL;
                }

                c = &loadcmds[nloadcmds++];
                c->mapstart = ALLOC_ALIGN_DOWN(ph->p_vaddr);
                c->mapend = ALLOC_ALIGN_UP(ph->p_vaddr + ph->p_filesz);
                c->dataend = ph->p_vaddr + ph->p_filesz;
                c->allocend = ph->p_vaddr + ph->p_memsz;
                c->mapoff = ALLOC_ALIGN_DOWN(ph->p_offset);

                /* Determine whether there is a gap between the last segment
                   and this one.  */
                if (nloadcmds > 1 && c[-1].mapend != c->mapstart)
                    has_holes = true;

                /* Optimize a common case.  */
                c->prot = 0;
                if (ph->p_flags & PF_R)
                    c->prot |= PAL_PROT_READ;
                if (ph->p_flags & PF_W)
                    c->prot |= PAL_PROT_WRITE;
                if (ph->p_flags & PF_X)
                    c->prot |= PAL_PROT_EXEC;
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

    if (nloadcmds == 0) {
        /* This only happens for a bogus object that will be caught with
           another error below.  But we don't want to go through the
           calculations below using NLOADCMDS - 1.  */
        print_error("object file has no loadable segments", -PAL_ERROR_INVAL);
        return NULL;
    }

    /* Now process the load commands and map segments into memory.  */
    c = loadcmds;

    /* Length of the sections to be loaded.  */
    maplength = loadcmds[nloadcmds - 1].allocend - c->mapstart;

#define APPEND_WRITECOPY(prot) ((prot)|PAL_PROT_WRITECOPY)

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
        void * mapaddr = NULL;
        /* Remember which part of the address space this object uses.  */
        ret = _DkStreamMap(handle, (void **) &mapaddr,
                           APPEND_WRITECOPY(c->prot), c->mapoff, maplength);

        if (ret < 0) {
            print_error("failed to map dynamic segment from shared object",
                        ret);
            return NULL;
        }

        l->l_map_start = (ElfW(Addr)) mapaddr;
        l->l_map_end = (ElfW(Addr)) mapaddr + maplength;
        l->l_addr = l->l_map_start - c->mapstart;

        if (has_holes)
            /* Change protection on the excess portion to disallow all access;
               the portions we do not remap later will be inaccessible as if
               unallocated.  Then jump into the normal segment-mapping loop to
               handle the portion of the segment past the end of the file
               mapping.  */
            _DkVirtualMemoryProtect((void *) (l->l_addr + c->mapend),
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

            if ((ret = _DkStreamMap(handle, &mapaddr, APPEND_WRITECOPY(c->prot),
                                    c->mapoff, c->mapend - c->mapstart)) < 0) {
                print_error("failed to map segment from shared object", ret);
                return NULL;
            }
        }

postmap:
        if (l->l_phdr == 0
            && (ElfW(Off)) c->mapoff <= header->e_phoff
            && ((c->mapend - c->mapstart + c->mapoff)
                >= header->e_phoff + header->e_phnum * sizeof (ElfW(Phdr))))
            /* Found the program header in this segment.  */
            l->l_phdr = (void *) (c->mapstart + header->e_phoff - c->mapoff);

        if (c->allocend > c->dataend) {
            /* Extra zero pages should appear at the end of this segment,
               after the data mapped from the file.   */
            ElfW(Addr) zero, zeroend, zerosec;

            zero = l->l_addr + c->dataend;
            zeroend = ALLOC_ALIGN_UP(l->l_addr + c->allocend);
            zerosec = ALLOC_ALIGN_UP(zero);

            if (zeroend < zerosec)
                /* All the extra data is in the last section of the segment.
                   We can just zero it.  */
                zerosec = zeroend;

            if (zerosec > zero) {
                /* Zero the final part of the last section of the segment.  */
                if ((c->prot & PAL_PROT_WRITE) == 0)
                {
                    /* Dag nab it.  */
                    ret = _DkVirtualMemoryProtect(
                        (void*)ALLOC_ALIGN_DOWN(zero), pal_state.alloc_align,
                        c->prot | PAL_PROT_WRITE);
                    if (ret < 0) {
                        print_error("cannot change memory protections", ret);
                        return NULL;
                    }
                }
                memset ((void *) zero, '\0', zerosec - zero);
                if ((c->prot & PAL_PROT_WRITE) == 0)
                    _DkVirtualMemoryProtect((void*)ALLOC_ALIGN_DOWN(zero),
                                            pal_state.alloc_align, c->prot);
            }

            if (zeroend > zerosec) {
                /* Map the remaining zero pages in from the zero fill FD. */
                void * mapat = (void *) zerosec;
                ret = _DkVirtualMemoryAlloc(&mapat, zeroend - zerosec,
                                            0, c->prot);
                if (ret < 0) {
                    print_error("cannot map zero-fill allocation", ret);
                    return NULL;
                }
            }
        }

        ++c;
    }

    if (l->l_ld == 0) {
        if (e_type == ET_DYN) {
            print_error("object file has no dynamic section",
                        -PAL_ERROR_INVAL);
            return NULL;
        }
    } else {
        l->l_real_ld = l->l_ld =
            (ElfW(Dyn) *) ((ElfW(Addr)) l->l_ld + l->l_addr);

        if (do_copy_dyn)
            l->l_ld = malloc_copy(l->l_ld, sizeof(ElfW(Dyn)) * l->l_ldnum);
    }

    elf_get_dynamic_info(l->l_ld, l->l_info, l->l_addr);

    if (l->l_phdr == NULL) {
        /* The program header is not contained in any of the segments.
           We have to allocate memory ourself and copy it over from out
           temporary place.  */
        ElfW(Phdr) * newp = (ElfW(Phdr) *) malloc (header->e_phnum
                                                   * sizeof (ElfW(Phdr)));
        if (!newp) {
            print_error("cannot allocate memory for program header",
                        -PAL_ERROR_NOMEM);
            return NULL;
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

int check_elf_magic (const void* header, size_t len)
{
#define ELF_MAGIC_SIZE EI_CLASS
    if (len < ELF_MAGIC_SIZE)
        return -PAL_ERROR_INVAL;

    ElfW(Ehdr) * ehdr = (ElfW(Ehdr) *) header;

    static const unsigned char expected[EI_CLASS] =
    {
        [EI_MAG0] = ELFMAG0,
        [EI_MAG1] = ELFMAG1,
        [EI_MAG2] = ELFMAG2,
        [EI_MAG3] = ELFMAG3,
    };

    /* See whether the ELF header is what we expect.  */
    if (memcmp(ehdr->e_ident, expected, ELF_MAGIC_SIZE) != 0)
        return -PAL_ERROR_INVAL;

    return 0;
}

int check_elf_object (PAL_HANDLE handle)
{
    unsigned char buffer[ELF_MAGIC_SIZE];
    int64_t len = _DkStreamRead(handle, 0, sizeof(buffer), buffer, NULL, 0);

    if (__builtin_expect(len < 0, 0))
        return len;
    return check_elf_magic(buffer, len);
}

void free_elf_object (struct link_map * map)
{
    _DkVirtualMemoryFree((void *) map->l_map_start,
                         map->l_map_end - map->l_map_start);

    if (map->l_prev)
        map->l_prev->l_next = map->l_next;
    if (map->l_next)
        map->l_next->l_prev = map->l_prev;

#ifdef DEBUG
    _DkDebugDelMap(map);
#endif

    if (loaded_maps == map)
        loaded_maps = map->l_next;

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

    ret = load_elf_object_by_handle(handle, type);

    _DkObjectClose(handle);
    return ret;
}

int add_elf_object(void * addr, PAL_HANDLE handle, int type)
{
    struct link_map * map = new_elf_object(_DkStreamRealpath(handle), type);
    const ElfW(Ehdr) * header = (void *) addr;
    const ElfW(Phdr) * ph, * phdr =
            (ElfW(Phdr) *) ((char *) addr + header->e_phoff);

    map->l_phdr  = (void *) header->e_phoff;
    map->l_phnum = header->e_phnum;

    ElfW(Addr) mapstart = ~0;  /* start with the highest possible address */
    ElfW(Addr) mapend = 0;     /* start with the lowest possible address */

    for (ph = phdr; ph < &phdr[map->l_phnum]; ++ph)
        switch (ph->p_type) {
            case PT_DYNAMIC:
                map->l_ld = (void *) ph->p_vaddr;
                map->l_ldnum = ph->p_memsz / sizeof (ElfW(Dyn));
                break;
            case PT_LOAD: {
                ElfW(Addr) start = (ElfW(Addr))ALLOC_ALIGN_DOWN(map->l_addr + ph->p_vaddr);
                ElfW(Addr) end = (ElfW(Addr))
                        ALLOC_ALIGN_UP(map->l_addr + ph->p_vaddr + ph->p_memsz);
                if (start < mapstart)
                    mapstart = start;
                if (end > mapend)
                    mapend = end;
            }
        }

    map->l_addr  = (ElfW(Addr)) addr - mapstart;
    map->l_entry = header->e_entry;
    map->l_map_start = (ElfW(Addr)) addr;
    map->l_map_end = (ElfW(Addr)) addr + (mapend - mapstart);

    map->l_real_ld = (ElfW(Dyn) *)
            ((char *) map->l_addr + (unsigned long) map->l_ld);
    map->l_ld = malloc_copy(map->l_real_ld, sizeof(ElfW(Dyn)) * map->l_ldnum);

    elf_get_dynamic_info(map->l_ld, map->l_info, map->l_addr);
    setup_elf_hash(map);
    ELF_DYNAMIC_RELOCATE(map);

    /* append to list (to preserve order of libs specified in
     * manifest, e.g., loader.preload)
     */
    map->l_next = NULL;
    if (!loaded_maps) {
        map->l_prev = NULL;
        loaded_maps = map;
    } else {
        struct link_map * end = loaded_maps;
        while (end->l_next)
            end = end->l_next;
        end->l_next = map;
        map->l_prev = end;
    }

    if (type == OBJECT_EXEC)
        exec_map = map;

#ifdef DEBUG
    _DkDebugAddMap(map);
#endif

    return 0;
}

static int relocate_elf_object (struct link_map *l);

#if CACHE_LOADED_BINARIES == 1

#define MAX_CACHED_LOADCMDS  32
struct cached_elf_object {
    PAL_NUM             instance_id;
    void *              loader_addr;    /* get the address of DkStreamOpen */
    struct link_map     map;
    char                map_name[80];

    struct cached_loadcmd {
        void * mapstart;
        unsigned long mapsize;
        unsigned long mapoff;
        int mapprot;
    } loadcmds[MAX_CACHED_LOADCMDS];
    int nloadcmds;

    ElfW(Dyn)           dyn[];
};

void cache_elf_object (PAL_HANDLE handle, struct link_map * map)
{
    char uri[URI_MAX];
    unsigned long cached_size = 0;

    int ret = _DkStreamGetName(handle, uri, URI_MAX);
    if (ret < 0)
        return;

    strcpy_static(uri + ret, ".cached", URI_MAX - ret);
    PAL_HANDLE cached_file;

    while (1) {
        ret = _DkStreamOpen(&cached_file, uri,
                            PAL_ACCESS_RDWR,
                            PAL_SHARE_OWNER_W|PAL_SHARE_OWNER_R,
                            PAL_CREATE_TRY|PAL_CREATE_ALWAYS, 0);

        if (ret != -PAL_ERROR_STREAMEXIST)
            break;

        if (_DkStreamOpen(&cached_file, uri, PAL_ACCESS_RDWR, 0, 0, 0) < 0)
            return;

        ret = _DkStreamDelete(cached_file, 0);
        _DkObjectClose(cached_file);
        if (ret < 0)
            return;
    }

    if (ret < 0)
        return;

    struct cached_elf_object * obj = NULL;
    unsigned long obj_size = sizeof(struct cached_elf_object);
    if (map->l_ld != map->l_real_ld)
        obj_size += sizeof(ElfW(Dyn)) * map->l_ldnum;
    obj_size = ALLOC_ALIGN_UP(obj_size);

    cached_size = obj_size;
    ret = _DkStreamSetLength(cached_file, obj_size);
    if (ret < 0)
        goto out;

    ret = _DkStreamMap(cached_file, (void **) &obj,
                       PAL_PROT_READ|PAL_PROT_WRITE, 0, obj_size);
    if (ret < 0)
        goto out;

    obj->instance_id = pal_state.instance_id;
    obj->loader_addr = (void *) DkStreamOpen;
    memcpy(&obj->map, map, sizeof(struct link_map));
    if (map->l_ld != map->l_real_ld) {
        obj->map.l_ld   = NULL;
        memcpy(obj->dyn, map->l_ld, sizeof(ElfW(Dyn)) * map->l_ldnum);
        for (int i = 0; i < ARRAY_SIZE(obj->map.l_info); i++)
            if (obj->map.l_info[i])
                obj->map.l_info[i] = (void *)obj->map.l_info[i] - (unsigned long)map->l_ld;
    }
    obj->map.l_name = NULL;
    memcpy(obj->map_name, map->l_name, sizeof(obj->map_name));
    obj->nloadcmds  = 0;

    const ElfW(Ehdr) * header = (void *) map->l_map_start;
    const ElfW(Phdr) * phdr = (void *) header + header->e_phoff, * ph;

    for (ph = phdr ; ph < &phdr[header->e_phnum] ; ph++)
        if (ph->p_type == PT_LOAD) {
            assert(obj->nloadcmds < MAX_CACHED_LOADCMDS);

            void* mapstart = (void*)ALLOC_ALIGN_DOWN(map->l_addr + ph->p_vaddr);
            void* mapend   = (void*)ALLOC_ALIGN_UP(map->l_addr + ph->p_vaddr + ph->p_memsz);
            unsigned long mapsize = mapend - mapstart;
            int mapprot = 0;
            void * cache_addr = NULL;

            if (ph->p_flags & PF_R)
                mapprot |= PAL_PROT_READ;
            if (ph->p_flags & PF_W)
                mapprot |= PAL_PROT_WRITE;
            if (ph->p_flags & PF_X)
                mapprot |= PAL_PROT_EXEC;

            ret = _DkStreamSetLength(cached_file, cached_size + mapsize);
            if (ret < 0)
                goto out_mapped;

            ret = _DkStreamMap(cached_file, &cache_addr,
                               PAL_PROT_READ|PAL_PROT_WRITE, cached_size,
                               mapsize);
            if (ret < 0)
                goto out_mapped;

            obj->loadcmds[obj->nloadcmds].mapstart = mapstart;
            obj->loadcmds[obj->nloadcmds].mapsize  = mapsize;
            obj->loadcmds[obj->nloadcmds].mapprot  = mapprot;
            obj->loadcmds[obj->nloadcmds].mapoff   = cached_size;
            obj->nloadcmds++;
            cached_size += mapsize;

            memcpy(cache_addr, mapstart, mapsize);

            ret = _DkStreamUnmap(cache_addr, mapsize);
            if (ret < 0)
                goto out_mapped;
        }

    ret = _DkStreamUnmap(obj, obj_size);
    if (ret < 0)
        return;

    _DkObjectClose(cached_file);
    return;

out_mapped:
    _DkStreamUnmap(obj, obj_size);
out:
    _DkStreamDelete(cached_file, 0);
    _DkObjectClose(cached_file);
}

struct link_map * check_cached_elf_object (PAL_HANDLE handle)
{
    char uri[URI_MAX];
    int ret = _DkStreamGetName(handle, uri, URI_MAX);
    if (ret < 0)
        return NULL;

    strcpy_static(uri + ret, ".cached", URI_MAX - ret);
    PAL_HANDLE cached_file;
    ret = _DkStreamOpen(&cached_file, uri, PAL_ACCESS_RDWR, 0, 0, 0);
    if (ret < 0)
        return NULL;

    struct cached_elf_object * obj = NULL;
    unsigned long obj_size = ALLOC_ALIGN_UP(sizeof(struct cached_elf_object));

    ret = _DkStreamMap(cached_file, (void **) &obj,
                       PAL_PROT_READ|PAL_PROT_WRITE|PAL_PROT_WRITECOPY,
                       0, obj_size);
    if (ret < 0)
        goto out;

    /* we want to check if there is a previously cached one, but if the
     * process is the first one, force to update the cached binary. */
    if (pal_state.instance_id != obj->instance_id)
        goto out_mapped;

    if (!obj->map.l_ld) {
        obj->map.l_ld = obj->dyn;
        for (int i = 0; i < ARRAY_SIZE(obj->map.l_info); i++)
            if (obj->map.l_info[i])
                obj->map.l_info[i] = (void*)obj->map.l_info[i] + (unsigned long)obj->map.l_ld;
    }

    struct cached_loadcmd * l = obj->loadcmds;
    struct cached_loadcmd * last = &obj->loadcmds[obj->nloadcmds - 1];

    if (l < last) {
        ret = _DkStreamMap(cached_file, &l->mapstart,
                           l->mapprot|PAL_PROT_WRITECOPY,
                           l->mapoff,
                           last->mapstart + last->mapsize - l->mapstart);
        if (ret < 0)
            goto out_more_mapped;

        ret = _DkVirtualMemoryProtect(l->mapstart + l->mapsize,
                                last->mapstart - (l->mapstart + l->mapsize),
                                PAL_PROT_NONE);
        if (ret < 0)
            goto out_more_mapped;

        l++;
    }

    for ( ; l <= last ; l++) {
        ret = _DkStreamMap(cached_file, &l->mapstart,
                           l->mapprot|PAL_PROT_WRITECOPY,
                           l->mapoff,
                           l->mapsize);
        if (ret < 0)
            goto out_more_mapped;
    }

    if ((void *) DkStreamOpen != obj->loader_addr) {
        for (int i = 0 ; i < obj->map.nrelocs ; i++)
            *obj->map.relocs[i] += (void *) DkStreamOpen - obj->loader_addr;
    }

    obj->map.l_name = obj->map_name;
    _DkObjectClose(cached_file);
    return &obj->map;

out_more_mapped:
    _DkStreamUnmap(obj->loadcmds[0].mapstart,
                   last->mapstart + last->mapsize - obj->loadcmds[0].mapstart);
out_mapped:
    _DkStreamUnmap(obj, obj_size);
out:
    _DkObjectClose(cached_file);
    return NULL;
}
#endif /* CACHE_LOADED_BINARIES == 1 */

int load_elf_object_by_handle (PAL_HANDLE handle, enum object_type type)
{
    struct link_map * map = NULL;
    char fb[FILEBUF_SIZE], * errstring;
    int ret = 0;

#if CACHE_LOADED_BINARIES == 1
    map = check_cached_elf_object(handle);
    if (map)
        goto done;
#endif

    /* Now we will start verify the file as a ELF header. This part of code
       is borrow from open_verify() */
    ElfW(Ehdr) * ehdr = (ElfW(Ehdr) *) &fb;
    ElfW(Phdr) * phdr = NULL;
    int phdr_malloced = 0;

    int len = _DkStreamRead(handle, 0, FILEBUF_SIZE, &fb, NULL, 0);

    if ((size_t)len < sizeof(ElfW(Ehdr))) {
        if (len < 0)
            ret = len;
        else
            ret = -PAL_ERROR_INVAL;
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

    /* See whether the ELF header is what we expect.  */
    if (memcmp(ehdr->e_ident, expected, EI_OSABI) != 0 || (
            ehdr->e_ident[EI_OSABI] != ELFOSABI_SYSV &&
            ehdr->e_ident[EI_OSABI] != ELFOSABI_LINUX)) {
        ret = -PAL_ERROR_INVAL;
        errstring = "ELF file with invalid header";
        goto verify_failed;
    }

    /* Chia-Che 11/23/13: Removing other checks, comparing the header
       should be enough */

    size_t maplength = ehdr->e_phnum * sizeof (ElfW(Phdr));

    /* if e_phoff + maplength is smaller than the data read */
    if (ehdr->e_phoff + maplength <= (size_t) len) {
        phdr = (void *) (&fb + ehdr->e_phoff);
    } else {
        /* ...otherwise, we have to read again */
        phdr = malloc (maplength);
        phdr_malloced = 1;

        ret = _DkStreamRead(handle, ehdr->e_phoff, maplength, phdr, NULL, 0);

        if (ret < 0 || (size_t)ret != maplength) {
            ret = -PAL_ERROR_INVAL;
            errstring = "cannot read file data";
            goto verify_failed;
        }
    }

    if (!(map = map_elf_object_by_handle(handle, type, &fb, len, true))) {
        ret = -PAL_ERROR_INVAL;
        errstring = "unexpected failure";
        goto verify_failed;
    }

    relocate_elf_object(map);

#if CACHE_LOADED_BINARIES == 1
    cache_elf_object(handle, map);
done:
#endif

    /* append to list (to preserve order of libs specified in
     * manifest, e.g., loader.preload)
     */
    map->l_next = NULL;
    if (!loaded_maps) {
        map->l_prev = NULL;
        loaded_maps = map;
    } else {
        struct link_map * end = loaded_maps;
        while (end->l_next)
            end = end->l_next;
        end->l_next = map;
        map->l_prev = end;
    }

    if (map->l_type == OBJECT_EXEC)
        exec_map = map;

#ifdef DEBUG
    _DkDebugAddMap(map);
#endif

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

/* Nested routine to check whether the symbol matches.  */
static inline __attribute_always_inline
ElfW(Sym) * check_match(ElfW(Sym) * sym, ElfW(Sym) * ref, const char * undef_name,
                        const char * strtab)
{
    unsigned int stt = ELFW(ST_TYPE) (sym->st_info);
    assert(ELF_RTYPE_CLASS_PLT == 1);

    if ((sym->st_value == 0 /* No value */ && stt != STT_TLS) || sym->st_shndx == SHN_UNDEF)
        return NULL;

    /* Ignore all but STT_NOTYPE, STT_OBJECT, STT_FUNC,
    STT_COMMON, STT_TLS, and STT_GNU_IFUNC since these are no
    code/data definitions.  */
#define ALLOWED_STT     \
        ((1 << STT_NOTYPE) | (1 << STT_OBJECT) | (1 << STT_FUNC)        \
       | (1 << STT_COMMON) | (1 << STT_TLS)    | (1 << STT_GNU_IFUNC))

    if (((1 << stt) & ALLOWED_STT) == 0)
        return NULL;

    if (sym != ref && memcmp(strtab + sym->st_name, undef_name,
        strlen(undef_name)))
        /* Not the symbol we are looking for.  */
        return NULL;

    /* There cannot be another entry for this symbol so stop here.  */
    return sym;
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
    const ElfW(Addr) * bitmask = map->l_gnu_bitmask;

    if (bitmask != NULL) {
        ElfW(Addr) bitmask_word = bitmask[(hash / __ELF_NATIVE_CLASS)
                                          & map->l_gnu_bitmask_idxbits];

        unsigned int hashbit1 = hash & (__ELF_NATIVE_CLASS - 1);
        unsigned int hashbit2 = (hash >> map->l_gnu_shift)
                                & (__ELF_NATIVE_CLASS - 1);

        if ((bitmask_word >> hashbit1) & (bitmask_word >> hashbit2) & 1) {
            Elf32_Word bucket = map->l_gnu_buckets
                                    [hash % map->l_nbuckets];

            if (bucket != 0) {
                const Elf32_Word *hasharr = &map->l_gnu_chain_zero[bucket];

                do
                    if (((*hasharr ^ hash) >> 1) == 0) {
                        symidx = hasharr - map->l_gnu_chain_zero;
                        sym = check_match (&symtab[symidx], ref, undef_name, strtab);
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
            sym = check_match (&symtab[symidx], ref, undef_name, strtab);
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
    ElfW(Sym) * sym;
    struct link_map * map = loaded_maps;
    struct sym_val weak_result = { .s = NULL, .m = NULL };

    for (; map ; map = map->l_next) {
        sym = do_lookup_map(ref, undef_name, fast_hash, hash, map);
        if (!sym)
            continue;

        switch (ELFW(ST_BIND)(sym->st_info)) {
            case STB_WEAK:
                /* Weak definition.  Use this value if we don't find another. */
                if (!weak_result.s) {
                    weak_result.s = sym;
                    weak_result.m = (struct link_map *) map;
                }
                break;
                /* FALLTHROUGH */
            case STB_GLOBAL:
            case STB_GNU_UNIQUE:
                /* success: */
                /* Global definition.  Just what we need.  */
                result->s = sym;
                result->m = (struct link_map *) map;
                return 1;
            default:
                /* Local symbols are ignored.  */
                break;
        }
    }

    if (weak_result.s) {
        *result = weak_result;
        return 1;
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

    if (current_value.s == NULL) {
        *ref = NULL;
        return NULL;
    }

    *ref = current_value.s;
    return current_value.m;
}

static int protect_relro (struct link_map * l)
{
    ElfW(Addr) start = ALLOC_ALIGN_DOWN(l->l_addr + l->l_relro_addr);
    ElfW(Addr) end = ALLOC_ALIGN_UP(l->l_addr + l->l_relro_addr +
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
            r->start = ALLOC_ALIGN_DOWN(ph->p_vaddr) + l->l_addr;
            r->len = ALLOC_ALIGN_UP(ph->p_vaddr + ph->p_memsz)
                     - ALLOC_ALIGN_DOWN(ph->p_vaddr);

            ret = _DkVirtualMemoryProtect((void *) r->start, r->len,
                                          PAL_PROT_READ|PAL_PROT_WRITE);
            if (ret < 0)
                return ret;

            r->prot = 0;
            if (ph->p_flags & PF_R)
                r->prot |= PAL_PROT_READ;
            if (ph->p_flags & PF_W)
                r->prot |= PAL_PROT_WRITE;
            if (ph->p_flags & PF_X)
                r->prot |= PAL_PROT_EXEC;
            r->next = textrels;
            textrels = r;
        }

#if PROFILING == 1
    unsigned long before_relocate = _DkSystemTimeQuery();
#endif

    /* Do the actual relocation of the object's GOT and other data.  */
    ELF_DYNAMIC_RELOCATE(l);

#if PROFILING == 1
    pal_state.relocation_time += _DkSystemTimeQuery() - before_relocate;
#endif

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

    return 0;
}

void DkDebugAttachBinary (PAL_STR uri, PAL_PTR start_addr)
{
#ifndef DEBUG
    __UNUSED(uri);
    __UNUSED(start_addr);
#else
    if (!strstartswith_static(uri, URI_PREFIX_FILE))
        return;

    const char * realname = uri + URI_PREFIX_FILE_LEN;
    struct link_map * l = new_elf_object(realname, OBJECT_EXTERNAL);

    /* This is the ELF header.  We read it in `open_verify'.  */
    const ElfW(Ehdr) * header = (ElfW(Ehdr) *) start_addr;

    l->l_entry = header->e_entry;
    l->l_phnum = header->e_phnum;
    l->l_map_start = (ElfW(Addr)) start_addr;

    ElfW(Phdr) * phdr = (void *) ((char *) start_addr + header->e_phoff);
    const ElfW(Phdr) * ph;
    ElfW(Addr) map_start = 0, map_end = 0;

    for (ph = phdr; ph < &phdr[l->l_phnum]; ++ph)
        if (ph->p_type == PT_PHDR) {
            if (!map_start || ph->p_vaddr < map_start)
                map_start = ph->p_vaddr;
            if (!map_end || ph->p_vaddr + ph->p_memsz > map_end)
                map_end = ph->p_vaddr + ph->p_memsz;
        }

    l->l_addr = l->l_map_start - map_start;
    l->l_map_end = l->l_addr + map_end;

    for (ph = phdr; ph < &phdr[l->l_phnum]; ++ph)
        switch (ph->p_type) {
            /* These entries tell us where to find things once the file's
               segments are mapped in.  We record the addresses it says
               verbatim, and later correct for the run-time load address.  */
            case PT_DYNAMIC:
                l->l_ld = l->l_real_ld = (ElfW(Dyn) *)
                        ((char *) l->l_addr + ph->p_vaddr);
                l->l_ldnum = ph->p_memsz / sizeof (ElfW(Dyn));
                break;

            case PT_PHDR:
                l->l_phdr = (ElfW(Phdr) *) ((char *) l->l_addr + ph->p_vaddr);
                break;

            case PT_GNU_RELRO:
                l->l_relro_addr = l->l_addr + ph->p_vaddr;
                l->l_relro_size = ph->p_memsz;
                break;
        }

    _DkDebugAddMap(l);
    free(l);
#endif
}

void DkDebugDetachBinary (PAL_PTR start_addr)
{
#ifndef DEBUG
    __UNUSED(start_addr);
#else
    for (struct link_map * l = loaded_maps; l; l = l->l_next)
        if (l->l_map_start == (ElfW(Addr)) start_addr) {
            _DkDebugDelMap(l);

            if (l->l_type == OBJECT_EXTERNAL)
                free_elf_object(l);
            break;
        }
#endif
}

#ifndef CALL_ENTRY
#ifdef __x86_64__
void * stack_before_call __attribute_unused = NULL;

#define CALL_ENTRY(l, cookies)                                          \
    ({  long ret;                                                       \
        __asm__ volatile(                                               \
                     "pushq $0\r\n"                                     \
                     "popfq\r\n"                                        \
                     "movq %%rsp, stack_before_call(%%rip)\r\n"         \
                     "leaq 1f(%%rip), %%rdx\r\n"                        \
                     "movq %2, %%rsp\r\n"                               \
                     "jmp *%1\r\n"                                      \
                     "1: movq stack_before_call(%%rip), %%rsp\r\n"      \
                                                                        \
                     : "=a"(ret) : "a"((l)->l_entry), "b"(cookies)      \
                     : "rcx", "rdx", "rdi", "rsi", "r8", "r9",          \
                       "r10", "r11", "memory", "cc");                   \
        ret; })
#else
# error "unsupported architecture"
#endif
#endif /* !CALL_ENTRY */

noreturn void start_execution(const char** arguments, const char** environs) {
    /* First we will try to run all the preloaded libraries which come with
       entry points */
    if (exec_map) {
        __pal_control.executable_range.start = (PAL_PTR) exec_map->l_map_start;
        __pal_control.executable_range.end   = (PAL_PTR) exec_map->l_map_end;
    }

#if PROFILING == 1
    unsigned long before_tail = _DkSystemTimeQuery();
#endif

    int narguments = 0;
    for (const char** a = arguments; *a ; a++, narguments++);

    /* Let's count the number of cookies, first we will have argc & argv */
    int ncookies = narguments + 3; /* 1 for argc, argc + 2 for argv */

    /* Then we count envp */
    for (const char** e = environs; *e; e++)
        ncookies++;

    ncookies++; /* for NULL-end */

    int cookiesz = sizeof(unsigned long int) * ncookies
                      + sizeof(ElfW(auxv_t)) * 1  /* only AT_NULL */
                      + sizeof(void *) * 4 + 16;

    unsigned long int* cookies = __alloca(cookiesz);
    int cnt = 0;

    /* Let's copy the cookies */
    cookies[cnt++] = (unsigned long int) narguments;

    for (int i = 0 ; arguments[i] ; i++)
        cookies[cnt++] = (unsigned long int) arguments[i];
    cookies[cnt++] = 0;
    for (int i = 0 ; environs[i]; i++)
        cookies[cnt++] = (unsigned long int) environs[i];
    cookies[cnt++] = 0;

    /* NOTE: LibOS implements its own ELF aux vectors. Any info from host's
     * aux vectors must be passed in PAL_CONTROL. Here we pass an empty list
     * of aux vectors for sanity. */
    ElfW(auxv_t) * auxv = (ElfW(auxv_t) *) &cookies[cnt];
    auxv[0].a_type = AT_NULL;
    auxv[0].a_un.a_val = 0;

#if PROFILING == 1
    __pal_control.startup_time = _DkSystemTimeQuery() - pal_state.start_time;
    __pal_control.tail_startup_time =
            pal_state.tail_startup_time += _DkSystemTimeQuery() - before_tail;
#endif

    for (struct link_map * l = loaded_maps; l ; l = l->l_next)
        if (l->l_type == OBJECT_PRELOAD && l->l_entry)
            CALL_ENTRY(l, cookies);

    if (exec_map)
        CALL_ENTRY(exec_map, cookies);

    _DkThreadExit(/*clear_child_tid=*/NULL);
}
