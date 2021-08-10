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

/*
 * Structure describing a loaded ELF object. Originally based on glibc link_map structure.
 */
struct link_map {
    /* Base address shared object is loaded at. */
    ElfW(Addr) l_addr;

    /* Object identifier: file path, or PAL URI if path is unavailable. */
    const char* l_name;

    /* Pointer to program header table. */
    ElfW(Phdr)* l_phdr;

    /* Entry point location. */
    ElfW(Addr) l_entry;

    /* Number of program header entries.  */
    ElfW(Half) l_phnum;

    /* Start and finish of memory map for this object.  l_map_start need not be the same as
     * l_addr. */
    ElfW(Addr) l_map_start, l_map_end;

    const char* l_interp_libname;

    /* Pointer to related file. */
    struct shim_handle* l_file;

    /* Size of all the data segments (including BSS), for setting up the brk region */
    size_t l_data_segment_size;
};

struct loadcmd {
    /*
     * Load command for a single segment. The following properties are true:
     *
     *   - start <= data_end <= map_end <= alloc_end
     *   - start, map_end, alloc_end are page-aligned
     *   - map_off is page-aligned
     *
     * The addresses are not relocated (i.e. you need to add l_addr to them).
     */

    /* Start of memory area */
    ElfW(Addr) start;

    /* End of file data (data_end .. alloc_end should be zeroed out) */
    ElfW(Addr) data_end;

    /* End of mapped file data (data_end rounded up to page size, so that we can mmap
     * start .. map_end) */
    ElfW(Addr) map_end;

    /* End of memory area */
    ElfW(Addr) alloc_end;

    /* File offset */
    uint64_t map_off;

    /* Permissions for memory area */
    int prot;
};

static struct link_map* g_exec_map = NULL;
static struct link_map* g_interp_map = NULL;

static int read_file_fragment(struct shim_handle* file, void* buf, size_t size, file_off_t offset);

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

static int read_loadcmd(const ElfW(Phdr)* ph, struct loadcmd* c) {
    assert(ph->p_type == PT_LOAD);

    if (ph->p_align > 1) {
        if (!IS_POWER_OF_2(ph->p_align)) {
            log_debug("%s: ELF load command alignment value is not a power of 2", __func__);
            return -EINVAL;
        }
        if (!IS_ALIGNED_POW2(ph->p_vaddr - ph->p_offset, ph->p_align)) {
            log_debug("%s: ELF load command address/offset not properly aligned", __func__);
            return -EINVAL;
        }
    }

    if (!IS_ALLOC_ALIGNED(ph->p_vaddr - ph->p_offset)) {
        log_debug("%s: ELF load command address/offset not page-aligned", __func__);
        return -EINVAL;
    }

    if (ph->p_filesz > ph->p_memsz) {
        log_debug("%s: file size larger than memory size", __func__);
        return -EINVAL;
    }

    c->start = ALLOC_ALIGN_DOWN(ph->p_vaddr);
    c->data_end = ph->p_vaddr + ph->p_filesz;
    c->map_end = ALLOC_ALIGN_UP(ph->p_vaddr + ph->p_filesz);
    c->alloc_end  = ALLOC_ALIGN_UP(ph->p_vaddr + ph->p_memsz);
    c->map_off = ALLOC_ALIGN_DOWN(ph->p_offset);
    assert(c->start <= c->data_end);
    assert(c->data_end <= c->map_end);
    assert(c->map_end <= c->alloc_end);

    c->prot = (((ph->p_flags & PF_R) ? PROT_READ : 0) |
               ((ph->p_flags & PF_W) ? PROT_WRITE : 0) |
               ((ph->p_flags & PF_X) ? PROT_EXEC : 0));

    return 0;
}

static int read_all_loadcmds(const ElfW(Phdr)* phdr, size_t phnum, size_t* n_loadcmds,
                             struct loadcmd** loadcmds) {
    const ElfW(Phdr)* ph;
    int ret;

    size_t n = 0;
    for (ph = phdr; ph < &phdr[phnum]; ph++)
        if (ph->p_type == PT_LOAD)
            n++;

    if (n == 0) {
        *n_loadcmds = 0;
        *loadcmds = NULL;
        return 0;
    }

    if ((*loadcmds = malloc(n * sizeof(**loadcmds))) == NULL) {
        log_debug("%s: failed to allocate memory", __func__);
        return -ENOMEM;
    }

    struct loadcmd* c = *loadcmds;
    const ElfW(Phdr)* ph_prev = NULL;
    for (ph = phdr; ph < &phdr[phnum]; ph++) {
        if (ph->p_type == PT_LOAD) {
            if (ph_prev && !(ph_prev->p_vaddr < ph->p_vaddr)) {
                log_debug("%s: PT_LOAD segments are not in ascending order", __func__);
                ret = -EINVAL;
                goto err;
            }

            ph_prev = ph;

            if ((ret = read_loadcmd(ph, c)) < 0)
                goto err;

            c++;
        }
    }

    *n_loadcmds = n;
    return 0;

err:
    *n_loadcmds = 0;
    free(*loadcmds);
    *loadcmds = NULL;
    return ret;
}

/*
 * Find an initial memory area for a shared object. This bookkeeps the area to make sure we can
 * access all of it, but doesn't actually map the memory: we will do that when loading the segments.
 */
static int reserve_dyn(size_t total_size, void** addr) {
    int ret;

    if ((ret = bkeep_mmap_any_aslr(ALLOC_ALIGN_UP(total_size), PROT_NONE, VMA_UNMAPPED,
                                   /*file=*/NULL, /*offset=*/0, /*comment=*/NULL, addr) < 0)) {
        log_debug("reserve_dyn: failed to find an address for shared object");
        return ret;
    }

    return 0;
}

/*
 * Execute a single load command: bookkeep the memory, map the file content, and make sure the area
 * not mapped to a file (ph_filesz .. ph_memsz) is zero-filled.
 *
 * This function doesn't undo allocations in case of error: if it fails, it may leave some segments
 * already allocated.
 */
static int execute_loadcmd(const struct loadcmd* c, ElfW(Addr) load_addr,
                           struct shim_handle* file) {
    int ret;
    int map_flags = MAP_FIXED | MAP_PRIVATE;
    PAL_FLG pal_prot = LINUX_PROT_TO_PAL(c->prot, map_flags);

    /* Map the part that should be loaded from file, rounded up to page size. */
    if (c->start < c->map_end) {
        void* map_start = (void*)(load_addr + c->start);
        size_t map_size = c->map_end - c->start;

        if ((ret = bkeep_mmap_fixed(map_start, map_size, c->prot, map_flags, file, c->map_off,
                                    /*comment=*/NULL)) < 0) {
            log_debug("%s: failed to bookkeep address of segment", __func__);
            return ret;
        }

        if ((ret = file->fs->fs_ops->mmap(file, &map_start, map_size, c->prot, map_flags,
                                          c->map_off) < 0)) {
            log_debug("%s: failed to map segment", __func__);
            return ret;
        }
    }

    /* Zero out the extra data at the end of mapped area. If necessary, temporarily remap the last
     * page as writable. */
    if (c->data_end < c->map_end) {
        void* zero_start = (void*)(load_addr + c->data_end);
        size_t zero_size = c->map_end - c->data_end;
        void* last_page_start = ALLOC_ALIGN_DOWN_PTR(zero_start);

        if ((c->prot & PROT_WRITE) == 0) {
            if ((ret = DkVirtualMemoryProtect(last_page_start, ALLOC_ALIGNMENT,
                                              pal_prot | PAL_PROT_WRITE) < 0)) {
                log_debug("%s: cannot change memory protections", __func__);
                return pal_to_unix_errno(ret);
            }
        }

        memset(zero_start, 0, zero_size);

        if ((c->prot & PROT_WRITE) == 0) {
            if ((ret = DkVirtualMemoryProtect(last_page_start, ALLOC_ALIGNMENT, pal_prot) < 0)) {
                log_debug("%s: cannot change memory protections", __func__);
                return pal_to_unix_errno(ret);
            }
        }
    }

    /* Allocate extra pages after the mapped area. */
    if (c->map_end < c->alloc_end) {
        void* zero_page_start = (void*)(load_addr + c->map_end);
        size_t zero_page_size = c->alloc_end - c->map_end;
        int zero_map_flags = MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS;
        PAL_FLG zero_pal_prot = LINUX_PROT_TO_PAL(c->prot, zero_map_flags);

        if ((ret = bkeep_mmap_fixed(zero_page_start, zero_page_size, c->prot, zero_map_flags,
                                    /*file=*/NULL, /*offset=*/0, /*comment=*/NULL)) < 0) {
            log_debug("%s: cannot bookkeep address of zero-fill pages", __func__);
            return ret;
        }

        if ((ret = DkVirtualMemoryAlloc(&zero_page_start, zero_page_size, /*alloc_type=*/0,
                                        zero_pal_prot)) < 0) {
            log_debug("%s: cannot map zero-fill pages", __func__);
            return pal_to_unix_errno(ret);
        }
    }

    return 0;
}

static struct link_map* map_elf_object(struct shim_handle* file, ElfW(Ehdr)* ehdr) {
    ElfW(Phdr)* phdr = NULL;
    ElfW(Addr) interp_libname_vaddr = 0;
    struct loadcmd* loadcmds = NULL;
    size_t n_loadcmds = 0;
    const char* errstring = NULL;
    int ret = 0;

    /* Check if the file is valid. */

    if (!(file && file->fs && file->fs->fs_ops))
        return NULL;

    if (!(file->fs->fs_ops->read && file->fs->fs_ops->mmap && file->fs->fs_ops->seek))
        return NULL;

    /* Allocate a new link_map. */

    const char* name = qstrgetstr(&file->uri);
    struct link_map* l = new_elf_object(name);

    if (!l)
        return NULL;

    /* Load the program header table. */

    size_t phdr_size = ehdr->e_phnum * sizeof(ElfW(Phdr));
    phdr = (ElfW(Phdr)*)malloc(phdr_size);
    if (!phdr) {
        errstring = "phdr malloc failure";
        ret = -ENOMEM;
        goto err;
    }
    if ((ret = read_file_fragment(file, phdr, phdr_size, ehdr->e_phoff)) < 0) {
        errstring = "cannot read phdr";
        goto err;
    }

    /* Scan the program header table load commands and additional information. */

    if ((ret = read_all_loadcmds(phdr, ehdr->e_phnum, &n_loadcmds, &loadcmds)) < 0) {
        errstring = "failed to read load commands";
        goto err;
    }

    if (n_loadcmds == 0) {
        /* This only happens for a malformed object, and the calculations below assume the loadcmds
         * array is not empty. */
        errstring = "object file has no loadable segments";
        ret = -EINVAL;
        goto err;
    }

    const ElfW(Phdr)* ph;
    for (ph = phdr; ph < &phdr[ehdr->e_phnum]; ph++) {
        if (ph->p_type == PT_INTERP) {
            interp_libname_vaddr = ph->p_vaddr;
        }
    }

    /* Determine the load address. */

    size_t load_start = loadcmds[0].start;
    size_t load_end = loadcmds[n_loadcmds - 1].alloc_end;

    if (ehdr->e_type == ET_DYN) {
        /*
         * This is a position-independent shared object, reserve a memory area to determine load
         * address.
         *
         * Note that we reserve memory starting from offset 0, not from load_start. This is to
         * ensure that the load base (l_addr) will not be lower than 0.
         */
        void* addr;

        if ((ret = reserve_dyn(load_end, &addr)) < 0) {
            errstring = "failed to allocate memory for shared object";
            goto err;
        }

        l->l_addr = (ElfW(Addr))addr;
    } else {
        l->l_addr = 0;
    }
    l->l_map_start = load_start + l->l_addr;
    l->l_map_end   = load_end + l->l_addr;

    /* Execute load commands. */
    l->l_data_segment_size = 0;
    for (struct loadcmd* c = &loadcmds[0]; c < &loadcmds[n_loadcmds]; c++) {
        if ((ret = execute_loadcmd(c, l->l_addr, file)) < 0) {
            errstring = "failed to execute load command";
            goto err;
        }

        if (!l->l_phdr && ehdr->e_phoff >= c->map_off
                && ehdr->e_phoff + phdr_size <= c->map_off + (c->data_end - c->start)) {
            /* Found the program header in this segment. */
            ElfW(Addr) phdr_vaddr = ehdr->e_phoff - c->map_off + c->start;
            l->l_phdr = (ElfW(Phdr)*)(phdr_vaddr + l->l_addr);
        }


        if (interp_libname_vaddr != 0 && !l->l_interp_libname && c->start <= interp_libname_vaddr
                && interp_libname_vaddr < c->data_end) {
            /* Found the interpreter name in this segment (but we need to validate length). */
            const char* interp_libname = (const char*)(interp_libname_vaddr + l->l_addr);
            size_t maxlen = c->data_end - interp_libname_vaddr;
            size_t len = strnlen(interp_libname, maxlen);
            if (len == maxlen) {
                errstring = "interpreter name is longer than mapped segment";
                ret = -EINVAL;
                goto err;
            }
            l->l_interp_libname = interp_libname;
        }

        if (ehdr->e_entry != 0 && !l->l_entry && c->start <= ehdr->e_entry
                && ehdr->e_entry < c->data_end) {
            /* Found the entry point in this segment. */
            l->l_entry = (ElfW(Addr))(ehdr->e_entry + l->l_addr);
        }

        if (!(c->prot & PROT_EXEC))
            l->l_data_segment_size += c->alloc_end - c->start;
    }

    /* Check if various fields were found in mapped segments (if specified at all). */

    if (!l->l_phdr) {
        errstring = "program header not found in any of the segments";
        ret = -EINVAL;
        goto err;
    }

    if (interp_libname_vaddr != 0 && !l->l_interp_libname) {
        errstring = "interpreter name not found in any of the segments";
        ret = -EINVAL;
        goto err;
    }

    if (ehdr->e_entry != 0 && !l->l_entry) {
        errstring = "entry point not found in any of the segments";
        ret = -EINVAL;
        goto err;
    }

    /* Fill in remaining link_map information. */

    l->l_phnum = ehdr->e_phnum;

    free(phdr);
    free(loadcmds);
    return l;

err:
    log_debug("loading %s: %s (%d)", l->l_name, errstring, ret);
    free(phdr);
    free(loadcmds);
    free(l);
    return NULL;
}

static void remove_elf_object(struct link_map* l) {
    remove_r_debug((void*)l->l_addr);
    free(l);
}

static int check_elf_header(ElfW(Ehdr)* ehdr) {
    const char* errstring __attribute__((unused));

#if __ELF_NATIVE_CLASS == 32
#define elf_class ELFCLASS32
#elif __ELF_NATIVE_CLASS == 64
#define elf_class ELFCLASS64
#else
#error "Unknown __ELF_NATIVE_CLASS" __ELF_NATIVE_CLASS
#define elf_class ELFCLASSNONE
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
#define byteorder  ELFDATA2MSB
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define byteorder ELFDATA2LSB
#else
#error "Unknown __BYTE_ORDER " __BYTE_ORDER
#define byteorder ELFDATANONE
#endif

    static const unsigned char expected[EI_NIDENT] = {
        [EI_MAG0] = ELFMAG0,       [EI_MAG1] = ELFMAG1,      [EI_MAG2] = ELFMAG2,
        [EI_MAG3] = ELFMAG3,       [EI_CLASS] = elf_class,   [EI_DATA] = byteorder,
        [EI_VERSION] = EV_CURRENT, [EI_OSABI] = 0,
    };

#undef elf_class
#undef byteorder

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
        errstring = "only ET_DYN and ET_EXEC can be loaded";
        goto verify_failed;
    }

    /* check if phentsize match the size of ElfW(Phdr) */
    if (ehdr->e_phentsize != sizeof(ElfW(Phdr))) {
        errstring = "ELF file's phentsize has unexpected size";
        goto verify_failed;
    }

    return 0;

verify_failed:
    log_debug("loading ELF file failed: %s", errstring);
    return -EINVAL;
}

static int read_file_fragment(struct shim_handle* file, void* buf, size_t size, file_off_t offset) {
    if (!file)
        return -EINVAL;

    if (!file->fs || !file->fs->fs_ops)
        return -EACCES;

    ssize_t (*read)(struct shim_handle*, void*, size_t)      = file->fs->fs_ops->read;
    file_off_t (*seek)(struct shim_handle*, file_off_t, int) = file->fs->fs_ops->seek;

    if (!read || !seek)
        return -EACCES;

    file_off_t seek_ret = seek(file, offset, SEEK_SET);
    if (seek_ret < 0)
        return seek_ret;

    ssize_t read_ret = read(file, buf, size);
    if (read_ret < 0)
        return read_ret;

    if ((size_t)read_ret < size)
        return -EINVAL;
    return 0;
}

static int load_elf_header(struct shim_handle* file, ElfW(Ehdr)* ehdr) {
    const char* errstring = NULL;
    int ret = read_file_fragment(file, ehdr, sizeof(*ehdr), /*offset=*/0);
    if (ret < 0) {
        errstring = "Failed to read ELF header from %s";
        ret = -ENOEXEC;
        goto err;
    }

    ret = check_elf_header(ehdr);
    if (ret < 0) {
        errstring = "%s is not an ELF executable. Please note that Graphene doesn't support "
                    "executing scripts as executables.";
        ret = -ENOEXEC;
        goto err;
    }

    return 0;
err:;
    char* path = NULL;
    if (file->dentry) {
        // This may fail, but we are already inside a more serious error handler.
        dentry_abs_path(file->dentry, &path, /*size=*/NULL);
    }
    log_error(errstring, path ? path : "(unknown)");
    free(path);
    return ret;
}

int check_elf_object(struct shim_handle* file) {
    ElfW(Ehdr) ehdr;
    return load_elf_header(file, &ehdr);
}

int load_elf_object(struct shim_handle* file, struct link_map** out_map) {
    int ret;
    const char* fname = file ? qstrgetstr(&file->uri) : "(unknown)";

    assert(file);
    log_debug("loading \"%s\"", fname);

    ElfW(Ehdr) ehdr;
    if ((ret = load_elf_header(file, &ehdr)) < 0)
        return ret;

    struct link_map* map = map_elf_object(file, &ehdr);
    if (!map) {
        log_error("Failed to map %s. This may be caused by the binary being non-PIE, in which "
                  "case Graphene requires a specially-crafted memory layout. You can enable it "
                  "by adding 'sgx.nonpie_binary = true' to the manifest.",
                  fname);
        return -EINVAL;
    }

    get_handle(file);
    map->l_file = file;

    if (map->l_file && !qstrempty(&map->l_file->uri)) {
        append_r_debug(qstrgetstr(&map->l_file->uri), (void*)map->l_addr);
    }

    *out_map = map;
    return 0;
}

static bool need_interp(struct link_map* exec_map) {
    return exec_map->l_interp_libname != NULL;
}

extern const char** g_library_paths;

static int find_interp(const char* interp_name, struct shim_dentry** out_dent) {
    size_t interp_name_len = strlen(interp_name);
    const char* filename = interp_name;
    size_t filename_len = interp_name_len;

    for (size_t i = 0; i < interp_name_len; i++) {
        if (interp_name[i] == '/') {
            filename = interp_name + i + 1;
            filename_len = interp_name_len - i - 1;
        }
    }

    const char* default_paths[] = {"/lib", "/lib64", NULL};
    const char** paths          = g_library_paths ?: default_paths;

    for (const char** path = paths; *path; path++) {
        size_t path_len = strlen(*path);
        char* interp_path = alloc_concat3(*path, path_len, "/", 1, filename, filename_len);
        if (!interp_path) {
            log_warning("%s: couldn't allocate path: %s/%s", __func__, *path, filename);
            return -ENOMEM;
        }

        log_debug("%s: searching for interpreter: %s", __func__, interp_path);
        struct shim_dentry* dent;
        int ret = path_lookupat(/*start=*/NULL, interp_path, LOOKUP_FOLLOW, &dent);
        if (ret == 0) {
            *out_dent = dent;
            return 0;
        }
    }

    return -ENOENT;
}

static int load_interp_object(struct link_map* exec_map) {
    assert(!g_interp_map);

    struct shim_dentry* dent;
    int ret;

    ret = find_interp(exec_map->l_interp_libname, &dent);
    if (ret < 0)
        return ret;

    struct shim_handle* hdl = get_new_handle();
    if (!hdl) {
        ret = -ENOMEM;
        goto out;
    }

    ret = dentry_open(hdl, dent, O_RDONLY);
    if (ret < 0)
        goto out;

    ret = load_elf_object(hdl, &g_interp_map);

out:
    if (hdl)
        put_handle(hdl);
    put_dentry(dent);
    return ret;
}

int load_elf_interp(struct link_map* exec_map) {
    if (!g_interp_map && need_interp(exec_map))
        return load_interp_object(exec_map);

    return 0;
}

void remove_loaded_elf_objects(void) {
    if (g_exec_map) {
        remove_elf_object(g_exec_map);
        g_exec_map = NULL;
    }
    if (g_interp_map) {
        remove_elf_object(g_interp_map);
        g_interp_map = NULL;
    }
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

int init_elf_objects(void) {
    int ret = 0;

    lock(&g_process.fs_lock);
    struct shim_handle* exec = g_process.exec;
    if (exec)
        get_handle(exec);
    unlock(&g_process.fs_lock);

    if (!exec)
        return 0;

    if (!g_exec_map) {
        /* Child processes should have received `g_exec_map` from parent */
        assert(!g_pal_control->parent_process);

        ret = load_elf_object(exec, &g_exec_map);
        if (ret < 0)
            goto out;
    }

    ret = init_brk_from_executable(g_exec_map);
    if (ret < 0)
        goto out;

    if (!g_interp_map && need_interp(g_exec_map) && (ret = load_interp_object(g_exec_map)) < 0)
        goto out;

    ret = 0;
out:
    put_handle(exec);
    return ret;
}

int init_brk_from_executable(struct link_map* exec_map) {
    return init_brk_region((void*)ALLOC_ALIGN_UP(exec_map->l_map_end),
                           exec_map->l_data_segment_size);
}

int register_library(const char* name, unsigned long load_address) {
    log_debug("glibc register library %s loaded at 0x%08lx", name, load_address);

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

noreturn void execute_elf_object(struct link_map* exec_map, void* argp, ElfW(auxv_t)* auxp) {
    if (exec_map) {
        /* If a new map is provided, it means we have cleared the existing one by calling
         * `remove_loaded_elf_objects`. This happens during `execve`. */
        assert(!g_exec_map);
        g_exec_map = exec_map;
    }
    assert(g_exec_map);

    int ret = vdso_map_init();
    if (ret < 0) {
        log_error("Could not initialize vDSO (error code = %d)", ret);
        process_exit(/*error_code=*/0, /*term_signal=*/SIGKILL);
    }

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
    auxp[0].a_un.a_val = (__typeof(auxp[0].a_un.a_val))g_exec_map->l_phdr;
    auxp[1].a_type     = AT_PHNUM;
    auxp[1].a_un.a_val = g_exec_map->l_phnum;
    auxp[2].a_type     = AT_PAGESZ;
    auxp[2].a_un.a_val = ALLOC_ALIGNMENT;
    auxp[3].a_type     = AT_ENTRY;
    auxp[3].a_un.a_val = g_exec_map->l_entry;
    auxp[4].a_type     = AT_BASE;
    auxp[4].a_un.a_val = g_interp_map ? g_interp_map->l_addr : 0;
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
        log_error("execute_elf_object: DkRandomBitsRead failed: %d", ret);
        DkProcessExit(1);
        /* UNREACHABLE */
    }
    auxp[5].a_un.a_val = random;

    ElfW(Addr) entry = g_interp_map ? g_interp_map->l_entry : g_exec_map->l_entry;

    CALL_ELF_ENTRY(entry, argp);

    die_or_inf_loop();
}

BEGIN_CP_FUNC(elf_object) {
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
END_CP_FUNC(elf_object)

BEGIN_RS_FUNC(elf_object) {
    __UNUSED(offset);
    struct link_map* map = (void*)(base + GET_CP_FUNC_ENTRY());

    CP_REBASE(map->l_name);
    CP_REBASE(map->l_file);
    DEBUG_RS("base=0x%08lx,name=%s", map->l_addr, map->l_name);
}
END_RS_FUNC(elf_object)

BEGIN_CP_FUNC(loaded_elf_objects) {
    __UNUSED(obj);
    __UNUSED(size);
    __UNUSED(objp);
    struct link_map* new_exec_map = NULL;
    struct link_map* new_interp_map = NULL;
    if (g_exec_map)
        DO_CP(elf_object, g_exec_map, &new_exec_map);
    if (g_interp_map)
        DO_CP(elf_object, g_interp_map, &new_interp_map);

    size_t off = ADD_CP_OFFSET(2 * sizeof(struct link_map*));
    struct link_map** maps = (void*)(base + off);
    maps[0] = new_exec_map;
    maps[1] = new_interp_map;

    ADD_CP_FUNC_ENTRY(off);
}
END_CP_FUNC(loaded_elf_objects)

BEGIN_RS_FUNC(loaded_elf_objects) {
    __UNUSED(base);
    __UNUSED(offset);
    struct link_map** maps = (void*)(base + GET_CP_FUNC_ENTRY());

    assert(!g_exec_map);
    g_exec_map = maps[0];
    if (g_exec_map)
        CP_REBASE(g_exec_map);

    assert(!g_interp_map);
    g_interp_map = maps[1];
    if (g_interp_map)
        CP_REBASE(g_interp_map);
}
END_RS_FUNC(loaded_elf_objects)
