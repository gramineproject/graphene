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
 * shim_rtld.c
 *
 * This file contains codes for dynamic loading of ELF binaries in library OS.
 * It's espeically used for loading interpreter (ld.so, in general) and
 * optimization of execve.
 * Most of the source codes are imported from GNU C library.
 */

#include <shim_internal.h>
#include <shim_table.h>
#include <shim_utils.h>
#include <shim_handle.h>
#include <shim_thread.h>
#include <shim_fs.h>
#include <shim_vma.h>
#include <shim_checkpoint.h>
#include <shim_profile.h>

#include <errno.h>
#include <elf.h>
#include <asm/prctl.h>
#include <asm/mman.h>

void * __load_address;
void * __load_address_end;

void * migrated_shim_addr __attribute_migratable = &__load_address;

/*
 * This structure is similar to glibc's link_map, but only contains
 * basic information needed for loading ELF binaries into memory
 * without relocation.
 */
struct link_map {
    void * base_addr;
    const char * binary_name;
    void * dynamic;
    void * map_start, * map_end;
    void * entry;
    const char * interp_name;
    void * phdr_addr;
    size_t phdr_num;
};

static struct link_map * exec_map, * interp_map;
static struct link_map shim_map;
static bool exec_reloaded = false;

int init_shim_map (void)
{
    shim_map.base_addr = (void *) &__load_address;
    shim_map.map_start = (void *) &__load_address;
    shim_map.map_end   = (void *) &__load_address_end;
    shim_map.binary_name = "libsysdb.so";
    return 0;
}

#if __WORDSIZE == 32
# define FILEBUF_SIZE 512
#else
# define FILEBUF_SIZE 832
#endif

extern const char ** library_paths;

static int load_link_map (struct link_map * map, struct shim_handle * file,
                          void * mapped_address)
{
    struct shim_mount * fs = file->fs;
    int ret;

    /* checking file operations */
    if (!fs || !fs->fs_ops)
        return -EINVAL;
    if (!fs->fs_ops->read)
        return -EINVAL;
    if (!fs->fs_ops->mmap)
        return -EINVAL;

    char filebuf[FILEBUF_SIZE];
    if (mapped_address) {
        memcpy(filebuf, mapped_address, FILEBUF_SIZE);
    } else {
        ret = fs->fs_ops->read(file, filebuf, FILEBUF_SIZE);
        if (ret < 0)
            return ret;
    }

    const Elf64_Ehdr * ehdr = (void *) filebuf;
    const Elf64_Phdr * phdr = (void *) filebuf + ehdr->e_phoff;
    const Elf64_Phdr * ph;
    void * map_start = (void *) -1, * map_end = NULL;

    memset(map, 0, sizeof(*map));

    for (ph = phdr ; ph < &phdr[ehdr->e_phnum] ; ph++)
        switch (ph->p_type) {
            case PT_DYNAMIC:
                map->dynamic = (void *) ph->p_vaddr;
                break;
            case PT_INTERP:
                map->interp_name = (const char *) ph->p_vaddr;
            case PT_LOAD: {
                void * start = (void *) ALIGN_DOWN(ph->p_vaddr);
                void * end = (void *) ALIGN_UP(ph->p_vaddr + ph->p_memsz);
                if (start < map_start)
                    map_start = start;
                if (end > map_end)
                    map_end = end;
                break;
            }
        }

    if (map_start >= map_end)
        return -EINVAL;

    void * map_base = NULL;

    if (mapped_address) {
        map_base = (void *) (mapped_address - map_start);
        ret = bkeep_mmap(map_base + (uintptr_t) map_start, map_end - map_start,
                         PROT_NONE,
                         MAP_FIXED|MAP_PRIVATE|MAP_FILE|VMA_UNMAPPED,
                         file, 0, NULL);
        if (ret < 0)
            return ret;
    } else {
        if (ehdr->e_type == ET_DYN) {
            void * addr = bkeep_unmapped_heap(map_end - map_start,
                                           PROT_NONE,
                                           MAP_PRIVATE|MAP_FILE|VMA_UNMAPPED,
                                           file, 0, NULL);
            if (!addr)
                return -ENOMEM;

            map_base = (void *) (addr - map_start);
        } else {
            ret = bkeep_mmap(map_start, map_end - map_start,
                             PROT_NONE,
                             MAP_FIXED|MAP_PRIVATE|MAP_FILE|VMA_UNMAPPED,
                             file, 0, NULL);
            if (ret < 0)
                return ret;
        }
    }

    for (ph = phdr ; ph < &phdr[ehdr->e_phnum] ; ph++) {
        if (ph->p_type != PT_LOAD)
            continue;

        void * start = (void *) ALIGN_DOWN(ph->p_vaddr);
        void * end = (void *) ALIGN_UP(ph->p_vaddr + ph->p_memsz);
        void * file_end = (void *) ALIGN_UP(ph->p_vaddr + ph->p_filesz);
        off_t  file_off = ALIGN_DOWN(ph->p_offset);
        void * map_addr = map_base + (uintptr_t) start;

        int prot = 0;
        if (ph->p_flags & PF_R)
            prot |= PROT_READ;
        if (ph->p_flags & PF_W)
            prot |= PROT_WRITE;
        if (ph->p_flags & PF_X)
            prot |= PROT_EXEC;

        bkeep_mmap(map_addr, file_end - start,
                   prot, MAP_PRIVATE|MAP_FILE|MAP_FIXED,
                   file, file_off, NULL);

        if (!mapped_address) {
            ret = fs->fs_ops->mmap(file, &map_addr, file_end - start, prot,
                                   MAP_PRIVATE|MAP_FILE|MAP_FIXED, file_off);
            if (ret < 0)
                return ret;
        }

        if (end > file_end) {
            map_addr = map_base + (uintptr_t) file_end;
            bkeep_mmap(map_addr, end - file_end, prot,
                       MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,
                       NULL, 0, NULL);

            if (!mapped_address) {
                void * mapped = DkVirtualMemoryAlloc(map_addr, end - file_end,
                                                     0, prot);
                assert(mapped == map_addr);
            }
        }
    }

    map->base_addr = map_base;
    map->dynamic   = map_base + (uintptr_t) map->dynamic;
    map->map_start = map_base + (uintptr_t) map_start;
    map->map_end   = map_base + (uintptr_t) map_end;
    map->entry     = map_base + (uintptr_t) ehdr->e_entry;
    map->phdr_addr = map->map_start + ehdr->e_phoff;
    map->phdr_num  = ehdr->e_phnum;

    if (map->interp_name) {
        const char * interp_name = map_base + (uintptr_t) map->interp_name;
        map->interp_name = malloc_copy(interp_name, strlen(interp_name));
    }

    append_r_debug(qstrgetstr(&file->uri), map->map_start, map->dynamic);

    return 0;
}

static int load_interp_map (struct link_map * exec)
{
    const char * interp_name = exec->interp_name;
    int len = strlen(interp_name);
    const char * filename = interp_name + len - 1;
    while (filename > interp_name && *filename != '/')
        filename--;
    if (*filename == '/')
        filename++;
    len -= filename - interp_name;

    const char * default_paths[] = { "/lib", "/lib64", NULL };
    const char ** paths = library_paths ? : default_paths;
    char interp_path[STR_SIZE];

    for (const char ** p = paths ; *p ; p++) {
        int plen = strlen(*p);
        memcpy(interp_path, *p, plen);
        interp_path[plen] = '/';
        memcpy(interp_path + plen + 1, filename, len + 1);

        debug("search interpreter: %s\n", interp_path);

        struct shim_dentry * dent = NULL;
        int ret = 0;

        if ((ret = path_lookupat(NULL, interp_path, LOOKUP_OPEN, &dent, NULL)) < 0 ||
            dent->state & DENTRY_NEGATIVE)
             continue;

        struct shim_mount * fs = dent->fs;
        get_dentry(dent);

        if (!fs->d_ops->open) {
            ret = -EACCES;
err:
            put_dentry(dent);
            return ret;
        }

        if (fs->d_ops->mode) {
            mode_t mode;
            if ((ret = fs->d_ops->mode(dent, &mode, 1)) < 0)
                goto err;
        }

        struct shim_handle * interp = NULL;

        if (!(interp = get_new_handle())) {
            ret = -ENOMEM;
            goto err;
        }

        set_handle_fs(interp, fs);
        interp->flags = O_RDONLY;
        interp->acc_mode = MAY_READ;

        if ((ret = fs->d_ops->open(interp, dent, O_RDONLY)) < 0) {
            put_handle(interp);
            goto err;
        }

        struct link_map * map = malloc(sizeof(struct link_map));
        if (!map) {
            ret = -ENOMEM;
            goto out;
        }

        ret = load_link_map(map, interp, NULL);
        if (!ret) {
            master_lock();
            if (exec_map == exec)
                interp_map = map;
            master_unlock();
        } else {
            free(map);
        }
out:
        put_handle(interp);
        return ret;
     }

    return -ENOENT;
}

int init_brk_from_executable (struct shim_handle * exec);

int init_loader (void)
{
    struct shim_thread * cur_thread = get_cur_thread();
    int ret = 0;

    lock(cur_thread->lock);
    struct shim_handle * exec = cur_thread->exec;
    if (exec)
        get_handle(exec);
    unlock(cur_thread->lock);

    if (!exec)
        return 0;

    if (!exec_map) {
        struct link_map * map = malloc(sizeof(struct link_map));
        if (!map)
            return -ENOMEM;

        if (PAL_CB(executable_range.start) && !exec_reloaded) {
            ret = load_link_map(map, exec, PAL_CB(executable_range.start));
            if (ret < 0)
                goto out;
        } else {
            ret = load_link_map(map, exec, NULL);
            if (ret < 0)
                goto out;
        }

        master_lock();
        exec_map = map;
        master_unlock();

        if (map->interp_name)
            load_interp_map(map);

        /*
         * Chia-Che 8/24/2017:
         * initialize brk region at the end of the executable data segment.
         */
        init_brk_region(exec_map->map_end);
    }

    ret = 0;
out:
    put_handle(exec);
    return ret;
}

int free_loader (void)
{
    struct link_map * old_exec_map = NULL, * old_interp_map = NULL;
    master_lock();

    if (exec_map) {
        old_exec_map = exec_map;
        exec_map = NULL;
    }

    if (interp_map) {
        old_interp_map = interp_map;
        interp_map = NULL;
    }

    exec_reloaded = true;
    master_unlock();
    free(old_exec_map);
    free(old_interp_map);
    return 0;
}

int execute_elf_object (struct shim_handle * exec, int argc, const char ** argp,
                        int nauxv, elf_auxv_t * auxp)
{
    assert(exec_map);

    auxp[0].a_type = AT_PHDR;
    auxp[0].a_un.a_val = (__typeof(auxp[0].a_un.a_val)) exec_map->phdr_addr;
    auxp[1].a_type = AT_PHNUM;
    auxp[1].a_un.a_val = exec_map->phdr_num;
    auxp[2].a_type = AT_PAGESZ;
    auxp[2].a_un.a_val = allocsize;
    auxp[3].a_type = AT_ENTRY;
    auxp[3].a_un.a_val = (uintptr_t) exec_map->entry;
    auxp[4].a_type = AT_BASE;
    auxp[4].a_un.a_val = interp_map ? (uintptr_t) interp_map->base_addr : 0;
    auxp[5].a_type = AT_NULL;

#if defined(__x86_64__)
    asm volatile (
                    "movq %%rbx, %%rsp\r\n"
                    "pushq %%rdi\r\n"
                    "jmp *%%rax\r\n"

                    :
                    : "a"(interp_map ? interp_map->entry : exec_map->entry),
                    "b"(argp),
                    "D"(argc)

                    : "memory");
#else
# error "architecture not supported"
#endif

    shim_do_exit(0);
    return 0;
}

BEGIN_CP_FUNC(link_map)
{
    assert(size == sizeof(struct link_map));

    struct link_map * map = (struct link_map *) obj;
    struct link_map * new_map;

    ptr_t off = ADD_CP_OFFSET(sizeof(struct link_map));
    ADD_TO_CP_MAP(obj, off);

    new_map = (struct link_map *) (base + off);
    memcpy(new_map, map, sizeof(*map));

    if (map->binary_name) {
        int namelen = strlen(map->binary_name);
        new_map->binary_name  = (char *) (base + ADD_CP_OFFSET(namelen + 1));
        memcpy((char *) new_map->binary_name, map->binary_name, namelen + 1);
    }

    ADD_CP_FUNC_ENTRY(off);
    *objp = new_map;
}
END_CP_FUNC(link_map)

BEGIN_RS_FUNC(link_map)
{
    struct link_map * map = (void *) (base + GET_CP_FUNC_ENTRY());

    CP_REBASE(map->binary_name);

    DEBUG_RS("addr=%p-%p,name=%s", map->map_start, map->map_end,
             map->binary_name);
}
END_RS_FUNC(link_map)

BEGIN_CP_FUNC(rtld)
{
    struct link_map * new_exec_map = NULL, * new_interp_map = NULL;
    master_lock();

    if (exec_map)
        DO_CP(link_map, exec_map, &new_exec_map);

    if (interp_map)
        DO_CP(link_map, interp_map, &new_interp_map);

    master_unlock();
    ADD_CP_FUNC_ENTRY(0);
    ADD_CP_ENTRY(ADDR, new_exec_map);
    ADD_CP_ENTRY(ADDR, new_interp_map);

#ifdef DEBUG
    DO_CP(gdb_map, NULL, NULL);
#endif
}
END_CP_FUNC(rtld)

BEGIN_RS_FUNC(rtld)
{
    master_lock();

    exec_map = (void *) GET_CP_ENTRY(ADDR);
    if (exec_map)
        CP_REBASE(exec_map);

    interp_map = (void *) GET_CP_ENTRY(ADDR);
    if (interp_map)
        CP_REBASE(interp_map);

    exec_reloaded = true;
    master_unlock();
}
END_RS_FUNC(rtld)
