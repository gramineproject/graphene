/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains code for loading ELF binaries in library OS. The source was originally based
 * on glibc (dl-load.c), but has been significantly modified since.
 *
 * Here is a short overview of the ELFs involved:
 *
 *  - PAL and LibOS binaries: not handled here (loaded before starting LibOS)
 *  - vDSO: loaded here
 *  - Program binary, and its interpreter (ld.so) if any: loaded here
 *  - Additional libraries: loaded by ld.so; only reported to PAL here (register_library)
 *
 * Note that we don't perform any dynamic linking here, just execute load commands and transfer
 * control to ld.so. In that regard, this file is more similar to Linux kernel (see binfmt_elf.c)
 * than glibc.
 */

#include <asm/mman.h>
#include <endian.h>
#include <errno.h>

#include "elf.h"
#include "elf/ldsodefs.h"
#include "shim_checkpoint.h"
#include "shim_entry.h"
#include "shim_flags_conv.h"
#include "shim_fs.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_lock.h"
#include "shim_process.h"
#include "shim_table.h"
#include "shim_utils.h"
#include "shim_vdso.h"
#include "shim_vdso-arch.h"
#include "shim_vma.h"

#ifndef DT_THISPROCNUM
#define DT_THISPROCNUM 0
#endif

typedef ElfW(Word) Elf_Symndx;

/*
 * Structure describing a loaded shared object. The `l_next' and `l_prev' members form a chain of
 * all the shared objects loaded at startup.
 *
 * Originally based on glibc link_map structure.
 */
struct link_map {
    /* Base address shared object is loaded at. */
    ElfW(Addr) l_addr;

    /* Object identifier: file path, or PAL URI if path is unavailable. */
    const char* l_name;

    /* Chain of loaded objects. */
    struct link_map* l_next;
    struct link_map* l_prev;

    /* Pointer to program header table, and whether it's allocated separately by us. */
    ElfW(Phdr)* l_phdr;
    bool l_phdr_allocated;

    /* Entry point location. */
    ElfW(Addr) l_entry;

    /* Number of program header entries.  */
    ElfW(Half) l_phnum;

    /* Start and finish of memory map for this object.  l_map_start need not be the same as
     * l_addr. */
    ElfW(Addr) l_map_start, l_map_end;

    const char* l_interp_libname;
    ElfW(Addr) l_main_entry;

    /* Pointer to related file. */
    struct shim_handle* l_file;

#define MAX_LOADCMDS 4
    struct loadcmd {
        ElfW(Addr) mapstart, mapend, dataend, allocend;
        off_t mapoff;
        int prot, flags;
        struct shim_vma* vma;
    } loadcmds[MAX_LOADCMDS];
    int nloadcmds;
};

#define RELOCATE(l, addr)  ((ElfW(Addr))(addr) + (ElfW(Addr))((l)->l_addr))

static struct link_map* loaded_libraries = NULL;
static struct link_map* interp_map = NULL;

static int read_file_fragment(struct shim_handle* file, void* buf, size_t offset, size_t size);

static struct link_map* new_elf_object(const char* realname) {
    struct link_map* new;

    new = (struct link_map*)malloc(sizeof(struct link_map));
    if (new == NULL)
        return NULL;

    /* We apparently expect this to be zeroed. */
    memset(new, 0, sizeof(struct link_map));
    new->l_name = realname;

    return new;
}

#if __BYTE_ORDER == __BIG_ENDIAN
#define byteorder ELFDATA2MSB
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define byteorder ELFDATA2LSB
#else
#error "Unknown __BYTE_ORDER " __BYTE_ORDER
#define byteorder ELFDATANONE
#endif

/* TODO: This function needs a cleanup and to be split into smaller parts. It is impossible to do
 * a proper cleanup on any failure right now. */
static struct link_map* __map_elf_object(struct shim_handle* file, ElfW(Ehdr)* ehdr) {
    ElfW(Phdr)* phdr = NULL;

    if (!(file && file->fs && file->fs->fs_ops))
        return NULL;

    if (!(file->fs->fs_ops->read && file->fs->fs_ops->mmap && file->fs->fs_ops->seek))
        return NULL;

    const char* name = !qstrempty(&file->path) ? qstrgetstr(&file->path) : qstrgetstr(&file->uri);
    struct link_map* l = new_elf_object(name);

    if (!l)
        return NULL;

    const char* errstring __attribute__((unused)) = NULL;
    int ret;

    /* Scan the program header table, collecting its load commands.  */
    struct loadcmd* c = l->loadcmds;

    /* Extract the remaining details we need from the ELF header
       and then read in the program header table.  */
    l->l_addr  = 0;
    l->l_entry = ehdr->e_entry;
    int e_type = ehdr->e_type;
    l->l_phnum = ehdr->e_phnum;

    size_t phdr_size = ehdr->e_phnum * sizeof(ElfW(Phdr));
    phdr = (ElfW(Phdr)*)malloc(phdr_size);
    if (!phdr) {
        errstring = "phdr malloc failure";
        goto call_lose;
    }
    if ((ret = read_file_fragment(file, phdr, ehdr->e_phoff, phdr_size)) < 0) {
        errstring = "cannot read phdr";
        goto call_lose;
    }
    l->l_phdr = phdr;

    l->nloadcmds   = 0;
    bool has_holes = false;

    const ElfW(Phdr)* ph;
    for (ph = phdr; ph < &phdr[l->l_phnum]; ++ph) {
        /* These entries tell us where to find things once the file's
           segments are mapped in.  We record the addresses it says
           verbatim, and later correct for the run-time load address.  */
        switch (ph->p_type) {
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
    size_t maplength = l->loadcmds[l->nloadcmds - 1].allocend - c->mapstart;

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

        static_assert(sizeof(mappref) == sizeof(void*), "Pointers size mismatch?!");
        ret = bkeep_mmap_any_aslr(ALLOC_ALIGN_UP(maplength), PROT_NONE, VMA_UNMAPPED, NULL,
                                  0, NULL, (void**)&mappref);
        if (ret < 0) {
            errstring = "failed to find an address for shared object";
            goto call_lose;
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
            ret = bkeep_mprotect((void*)RELOCATE(l, c->mapend),
                                 l->loadcmds[l->nloadcmds - 1].mapstart - c->mapend, PROT_NONE,
                                 /*is_internal=*/false);
            if (ret < 0) {
                errstring = "failed to bookkeep permissions change";
                goto call_lose;
            }
            ret = DkVirtualMemoryProtect((void*)RELOCATE(l, c->mapend),
                                         l->loadcmds[l->nloadcmds - 1].mapstart - c->mapend,
                                         PAL_PROT_NONE);
            if (ret < 0) {
                /* XXX: this often fails, because the above address might not be allocated.
                 * We need to rewrite this function soon.
                 errstring = "failed to change permissions";
                 goto call_lose;
                */
                ret = 0;
            }
        }

        goto do_remap;
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
            if (is_in_adjacent_user_vmas(mapaddr, c->mapend - c->mapstart)) {
                log_error("ELF already mapped: %s\n", l->l_name);
                goto call_lose;
            }

            ret = bkeep_mmap_fixed(mapaddr, c->mapend - c->mapstart, c->prot,
                                   c->flags | MAP_FIXED | MAP_PRIVATE,
                                   file, c->mapoff, NULL);
            if (ret < 0) {
                errstring = "failed to bookkeep address of segment from shared object";
                goto call_lose;
            }

            if (file->fs->fs_ops->mmap(file, &mapaddr, c->mapend - c->mapstart, c->prot,
                                       c->flags | MAP_FIXED | MAP_PRIVATE, c->mapoff) < 0) {
                errstring = "failed to map segment from shared object";
                goto call_lose;
            }
        }

        if (l->l_phdr == 0 && (ElfW(Off))c->mapoff <= ehdr->e_phoff
                && ((size_t)(c->mapend - c->mapstart + c->mapoff) >= phdr_size)) {
            /* Found the program header in this segment.  */
            l->l_phdr = (void*)(c->mapstart + ehdr->e_phoff - c->mapoff);
        }

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

            if (zeropage > zero) {
                /* Zero the final part of the last page of the segment.  */
                if ((c->prot & PROT_WRITE) == 0) {
                    /* Dag nab it.  */
                    if (DkVirtualMemoryProtect((caddr_t)ALLOC_ALIGN_DOWN(zero), g_pal_alloc_align,
                                               LINUX_PROT_TO_PAL(c->prot, /*map_flags=*/0)
                                                   | PAL_PROT_WRITE) < 0) {
                        errstring = "cannot change memory protections";
                        goto call_lose;
                    }
                    memset((void*)zero, '\0', zeropage - zero);
                    if (DkVirtualMemoryProtect((caddr_t)ALLOC_ALIGN_DOWN(zero), g_pal_alloc_align,
                                               LINUX_PROT_TO_PAL(c->prot, /*map_flags=*/0)) < 0) {
                        errstring = "cannot change memory protections";
                        goto call_lose;
                    }
                } else {
                    memset((void*)zero, '\0', zeropage - zero);
                }
            }

            if (zeroend > zeropage) {
                ret = bkeep_mmap_fixed((void*)zeropage, zeroend - zeropage, c->prot,
                                       MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
                                       NULL, 0, NULL);
                if (ret < 0) {
                    errstring = "cannot bookkeep address of zero-fill pages";
                    goto call_lose;
                }

                void* mapat = (void*)zeropage;
                ret = DkVirtualMemoryAlloc(&mapat, zeroend - zeropage, /*alloc_type=*/0,
                                           LINUX_PROT_TO_PAL(c->prot, /*map_flags=*/0));
                if (ret < 0) {
                    errstring = "cannot map zero-fill pages";
                    goto call_lose;
                }
            }
        }

        ++c;
    }

    if (l->l_phdr == NULL) {
        /* The program header is not contained in any of the segments. We have to allocate memory
         * ourselves. */
        ElfW(Phdr)* newp = malloc(phdr_size);
        if (newp == NULL) {
            errstring = "cannot allocate memory for program header";
            goto call_lose;
        }

        l->l_phdr = memcpy(newp, phdr, phdr_size);
        l->l_phdr_allocated = true;
    } else {
        /* Adjust the PT_PHDR value by the runtime load address.  */
        l->l_phdr = (ElfW(Phdr)*)RELOCATE(l, l->l_phdr);
    }
    l->l_entry = RELOCATE(l, l->l_entry);

    free(phdr);
    return l;

call_lose:
    log_debug("loading %s: %s\n", l->l_name, errstring);
    free(phdr);
    free(l);
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

    if (l->l_phdr_allocated)
        free(l->l_phdr);

    free(l);

    return 0;
}

static int __check_elf_header(ElfW(Ehdr)* ehdr) {
    const char* errstring __attribute__((unused));

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
    if (ehdr->e_machine != SHIM_ELF_HOST_MACHINE) {
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
    log_debug("load runtime object: %s\n", errstring);
    return -EINVAL;
}

static int read_file_fragment(struct shim_handle* file, void* buf, size_t offset, size_t size) {
    if (!file)
        return -EINVAL;

    if (!file->fs || !file->fs->fs_ops)
        return -EACCES;

    ssize_t (*read)(struct shim_handle*, void*, size_t) = file->fs->fs_ops->read;
    off_t (*seek)(struct shim_handle*, off_t, int)      = file->fs->fs_ops->seek;

    if (!read || !seek)
        return -EACCES;

    ssize_t ret;
    if ((ret = (*seek)(file, offset, SEEK_SET)) < 0)
        return ret;
    if ((ret = (*read)(file, buf, size)) < 0)
        return ret;
    if ((size_t)ret < size)
        return -EINVAL;
    return 0;
}

static int __load_elf_header(struct shim_handle* file, ElfW(Ehdr)* ehdr) {
    int ret = read_file_fragment(file, ehdr, /*offset=*/0, sizeof(*ehdr));
    if (ret < 0)
        return ret;

    ret = __check_elf_header(ehdr);
    if (ret < 0)
        return ret;

    return 0;
}

int check_elf_object(struct shim_handle* file) {
    ElfW(Ehdr) ehdr;

    int ret = read_file_fragment(file, &ehdr, /*offset=*/0, sizeof(ehdr));
    if (ret < 0)
        return ret;

    return __check_elf_header(&ehdr);
}

static int __load_elf_object(struct shim_handle* file);

int load_elf_object(struct shim_handle* file) {
    if (!file)
        return -EINVAL;

    log_debug("loading \"%s\"\n", file ? qstrgetstr(&file->uri) : "(unknown)");

    return __load_elf_object(file);
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

static int __load_elf_object(struct shim_handle* file) {
    int ret;

    ElfW(Ehdr) ehdr;
    if ((ret = __load_elf_header(file, &ehdr)) < 0)
        return ret;

    struct link_map* map = __map_elf_object(file, &ehdr);

    if (!map)
        return -EINVAL;

    if (file) {
        get_handle(file);
        map->l_file = file;
    }

    add_link_map(map);

    if (map->l_file && !qstrempty(&map->l_file->uri)) {
        append_r_debug(qstrgetstr(&map->l_file->uri), (void*)map->l_addr);
    }

    return ret;
}

struct sym_val {
    ElfW(Sym)* s;
    struct link_map* m;
};

static bool __need_interp(struct link_map* exec_map) {
    return exec_map->l_interp_libname != NULL;
}

extern const char** library_paths;

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

        log_debug("searching for interpreter: %s\n", interp_path);

        struct shim_dentry* dent = NULL;
        int ret = 0;

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

        if (!(ret = __load_elf_object(interp)))
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

static void* vdso_addr __attribute_migratable = NULL;

static int vdso_map_init(void) {
    /*
     * Allocate vdso page as user program allocated it.
     * Using directly vdso code in LibOS causes trouble when emulating fork.
     * In host child process, LibOS may or may not be loaded at the same address.
     * When LibOS is loaded at different address, it may overlap with the old vDSO
     * area.
     */
    void* addr = NULL;
    int ret = bkeep_mmap_any_aslr(ALLOC_ALIGN_UP(vdso_so_size), PROT_READ | PROT_EXEC,
                                  MAP_PRIVATE | MAP_ANONYMOUS, NULL, 0, LINUX_VDSO_FILENAME,
                                  &addr);
    if (ret < 0) {
        return ret;
    }

    ret = DkVirtualMemoryAlloc(&addr, ALLOC_ALIGN_UP(vdso_so_size), /*alloc_type=*/0,
                               PAL_PROT_READ | PAL_PROT_WRITE);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }

    memcpy(addr, &vdso_so, vdso_so_size);
    memset(addr + vdso_so_size, 0, ALLOC_ALIGN_UP(vdso_so_size) - vdso_so_size);

    ret = DkVirtualMemoryProtect(addr, ALLOC_ALIGN_UP(vdso_so_size), PAL_PROT_READ | PAL_PROT_EXEC);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }

    vdso_addr = addr;
    return 0;
}

int init_loader(void) {
    int ret = 0;

    lock(&g_process.fs_lock);
    struct shim_handle* exec = g_process.exec;
    if (exec)
        get_handle(exec);
    unlock(&g_process.fs_lock);

    if (!exec)
        return 0;

    struct link_map* exec_map = __search_map_by_handle(exec);

    if (!exec_map) {
        ret = load_elf_object(exec);
        if (ret < 0) {
            // TODO: Actually verify that the non-PIE-ness was the real cause of loading failure.
            log_error("ERROR: Failed to load %s. This may be caused by the binary being non-PIE, "
                      "in which case Graphene requires a specially-crafted memory layout. You can "
                      "enable it by adding 'sgx.nonpie_binary = 1' to the manifest.\n",
                      qstrgetstr(&exec->path));
            goto out;
        }

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
    if (!exec_map) {
        return -EINVAL;
    }

    size_t data_segment_size = 0;
    // Count all the data segments (including BSS)
    struct loadcmd* c = exec_map->loadcmds;
    for (; c < &exec_map->loadcmds[exec_map->nloadcmds]; c++)
        if (!(c->prot & PROT_EXEC))
            data_segment_size += c->allocend - c->mapstart;

    return init_brk_region((void*)ALLOC_ALIGN_UP(exec_map->l_map_end), data_segment_size);
}

int register_library(const char* name, unsigned long load_address) {
    log_debug("glibc register library %s loaded at 0x%08lx\n", name, load_address);

    struct shim_handle* hdl = get_new_handle();

    if (!hdl)
        return -ENOMEM;

    int err = open_namei(hdl, NULL, name, O_RDONLY, 0, NULL);
    if (err < 0) {
        put_handle(hdl);
        return err;
    }

    append_r_debug(qstrgetstr(&hdl->uri), (void*)load_address);
    put_handle(hdl);
    return 0;
}

noreturn void execute_elf_object(struct shim_handle* exec, void* argp, ElfW(auxv_t)* auxp) {
    int ret = vdso_map_init();
    if (ret < 0) {
        log_error("Could not initialize vDSO (error code = %d)", ret);
        process_exit(/*error_code=*/0, /*term_signal=*/SIGKILL);
    }

    struct link_map* exec_map = __search_map_by_handle(exec);
    assert(exec_map);

    /* at this point, stack looks like this:
     *
     *               +-------------------+
     *   argp +--->  |  argc             | long
     *               |  ptr to argv[0]   | char*
     *               |  ...              | char*
     *               |  NULL             | char*
     *               |  ptr to envp[0]   | char*
     *               |  ...              | char*
     *               |  NULL             | char*
     *               |  <space for auxv> |
     *               |  envp[0] string   |
     *               |  ...              |
     *               |  argv[0] string   |
     *               |  ...              |
     *               +-------------------+
     */
    assert(IS_ALIGNED_PTR(argp, 16)); /* stack must be 16B-aligned */

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
    ret = DkRandomBitsRead((PAL_PTR)random, 16);
    if (ret < 0) {
        log_error("execute_elf_object: DkRandomBitsRead failed: %d\n", ret);
        DkProcessExit(1);
        /* UNREACHABLE */
    }
    auxp[5].a_un.a_val = random;

    ElfW(Addr) entry = interp_map ? interp_map->l_entry : exec_map->l_entry;

    /* We are done with using this handle. */
    put_handle(exec);

    CALL_ELF_ENTRY(entry, argp);

    die_or_inf_loop();
}

BEGIN_CP_FUNC(library) {
    __UNUSED(size);
    assert(size == sizeof(struct link_map));

    struct link_map* map = (struct link_map*)obj;
    struct link_map* new_map;

    size_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off = ADD_CP_OFFSET(sizeof(struct link_map));
        ADD_TO_CP_MAP(obj, off);

        new_map = (struct link_map*)(base + off);
        memcpy(new_map, map, sizeof(struct link_map));

        new_map->l_prev   = NULL;
        new_map->l_next   = NULL;

        if (map->l_file)
            DO_CP_MEMBER(handle, map, new_map, l_file);

        if (map->l_name) {
            size_t namelen = strlen(map->l_name);
            char* name     = (char*)(base + ADD_CP_OFFSET(namelen + 1));
            memcpy(name, map->l_name, namelen + 1);
            new_map->l_name = name;
        }

        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_map = (struct link_map*)(base + off);
    }

    if (objp)
        *objp = (void*)new_map;
}
END_CP_FUNC(library)

BEGIN_RS_FUNC(library) {
    __UNUSED(offset);
    struct link_map* map = (void*)(base + GET_CP_FUNC_ENTRY());

    CP_REBASE(map->l_name);
    CP_REBASE(map->l_file);

    struct link_map* old_map = __search_map_by_name(map->l_name);

    if (old_map)
        remove_r_debug((void*)old_map->l_addr);

    if (old_map)
        replace_link_map(map, old_map);
    else
        add_link_map(map);

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

        DO_CP(library, map, &new_map);

        if (map == interp_map)
            new_interp_map = new_map;

        map = map->l_next;
    }

    ADD_CP_FUNC_ENTRY((uintptr_t)new_interp_map);
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
