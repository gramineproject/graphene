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
 * shim_checkpoint.c
 *
 * This file contains codes for checkpoint / migration scheme of library OS.
 */

#include <shim_internal.h>
#include <shim_utils.h>
#include <shim_thread.h>
#include <shim_handle.h>
#include <shim_vma.h>
#include <shim_fs.h>
#include <shim_checkpoint.h>
#include <shim_ipc.h>
#include <shim_profile.h>

#include <pal.h>
#include <pal_error.h>
#include <list.h>

#include <stdarg.h>
#include <asm/fcntl.h>
#include <asm/mman.h>

DEFINE_PROFILE_CATAGORY(migrate, );

DEFINE_PROFILE_CATAGORY(checkpoint, migrate);
DEFINE_PROFILE_INTERVAL(checkpoint_create_map,  checkpoint);
DEFINE_PROFILE_INTERVAL(checkpoint_copy,        checkpoint);
DEFINE_PROFILE_CATAGORY(checkpoint_func,        checkpoint);
DEFINE_PROFILE_INTERVAL(checkpoint_destroy_map, checkpoint);

DEFINE_PROFILE_OCCURENCE(checkpoint_count,      checkpoint);
DEFINE_PROFILE_OCCURENCE(checkpoint_total_size, checkpoint);

DEFINE_PROFILE_CATAGORY(resume, migrate);
DEFINE_PROFILE_INTERVAL(child_created_in_new_process,  resume);
DEFINE_PROFILE_INTERVAL(child_wait_header,             resume);
DEFINE_PROFILE_INTERVAL(child_receive_header,          resume);
DEFINE_PROFILE_INTERVAL(do_migration,                  resume);
DEFINE_PROFILE_INTERVAL(child_load_checkpoint_by_gipc, resume);
DEFINE_PROFILE_INTERVAL(child_load_memory_by_gipc,     resume);
DEFINE_PROFILE_INTERVAL(child_load_checkpoint_on_pipe, resume);
DEFINE_PROFILE_INTERVAL(child_receive_handles,         resume);
DEFINE_PROFILE_INTERVAL(restore_checkpoint,            resume);
DEFINE_PROFILE_CATAGORY(resume_func,                   resume);
DEFINE_PROFILE_INTERVAL(child_total_migration_time,    resume);

#define CP_HASH_SIZE    256
#define CP_HASH(addr) ((hashfunc((ptr_t)(addr))) & (CP_HASH_SIZE - 1))

typedef uint16_t FASTHASHTYPE;

#define CP_MAP_ENTRY_NUM 64

DEFINE_LIST(cp_map_entry);
struct cp_map_entry
{
    LIST_TYPE(cp_map_entry) hlist;
    struct shim_cp_map_entry entry;
};

DEFINE_LISTP(cp_map_entry);
struct cp_map {
    struct cp_map_buffer {
        struct cp_map_buffer * next;
        int num, cnt;
        struct cp_map_entry entries[0];
    } * buffers;

    struct hash_map {
        LISTP_TYPE(cp_map_entry) head[CP_HASH_SIZE];
    } map;
};

void * create_cp_map (void)
{
    void * data = malloc(sizeof(struct cp_map) + sizeof(struct cp_map_buffer) +
                         sizeof(struct cp_map_entry) * CP_MAP_ENTRY_NUM);

    if (!data)
        return NULL;

    struct cp_map * map = (struct cp_map *) data;
    struct cp_map_buffer * buffer =
                    (struct cp_map_buffer *) (data + sizeof(struct cp_map));

    memset(map, 0, sizeof(*map));
    map->buffers = buffer;
    buffer->next = NULL;
    buffer->num  = CP_MAP_ENTRY_NUM;
    buffer->cnt  = 0;

    return (void *) map;
}

void destroy_cp_map (void * map)
{
    struct cp_map * m = (struct cp_map *) map;
    struct cp_map_buffer * buffer = m->buffers, * next;

    for (next = buffer ? buffer->next : NULL ;
         buffer && next ;
         buffer = next, next = next ? next->next : NULL)
        free(buffer);

    free(m);
}

static inline
struct cp_map_buffer * extend_cp_map (struct cp_map * map)
{
    struct cp_map_buffer * buffer =
                malloc(sizeof(struct cp_map_buffer) +
                       sizeof(struct cp_map_entry) * CP_MAP_ENTRY_NUM);

    if (!buffer)
        return NULL;

    buffer->next = map->buffers;
    map->buffers = buffer;
    buffer->num  = CP_MAP_ENTRY_NUM;
    buffer->cnt  = 0;

    return buffer;
}

struct shim_cp_map_entry *
get_cp_map_entry (void * map, void * addr, bool create)
{
    struct cp_map * m = (struct cp_map *) map;

    FASTHASHTYPE hash = CP_HASH(addr);
    LISTP_TYPE(cp_map_entry) * head = &m->map.head[hash];
    struct cp_map_entry * tmp;
    struct shim_cp_map_entry * e = NULL;

    listp_for_each_entry(tmp, head, hlist)
        if (tmp->entry.addr == addr)
            e = &tmp->entry;

    if (create && !e) {
        struct cp_map_buffer * buffer = m->buffers;

        if (buffer->cnt == buffer->num)
            buffer = extend_cp_map(m);

        struct cp_map_entry *new = &buffer->entries[buffer->cnt++];
        INIT_LIST_HEAD(new, hlist);
        listp_add(new, head, hlist);

        new->entry.addr = addr;
        new->entry.off  = 0;
        e = &new->entry;
    }

    return e;
}

BEGIN_CP_FUNC(memory)
{
    struct shim_mem_entry * entry =
            (void *) (base + ADD_CP_OFFSET(sizeof(struct shim_mem_entry)));

    entry->addr  = obj;
    entry->size  = size;
    entry->paddr = NULL;
    entry->prot  = PAL_PROT_READ|PAL_PROT_WRITE;
    entry->data  = NULL;
    entry->prev  = store->last_mem_entry;
    store->last_mem_entry = entry;
    store->mem_nentries++;
    store->mem_size += size;

    if (objp)
        *objp = entry;
}
END_CP_FUNC_NO_RS(memory)

BEGIN_CP_FUNC(palhdl)
{
    ptr_t off = ADD_CP_OFFSET(sizeof(struct shim_palhdl_entry));
    struct shim_palhdl_entry * entry = (void *) (base + off);

    entry->handle = (PAL_HANDLE) obj;
    entry->uri = NULL;
    entry->phandle = NULL;
    entry->prev = store->last_palhdl_entry;
    store->last_palhdl_entry = entry;
    store->palhdl_nentries++;

    ADD_CP_FUNC_ENTRY(off);

    if (objp)
        *objp = entry;
}
END_CP_FUNC(palhdl)

BEGIN_RS_FUNC(palhdl)
{
    struct shim_palhdl_entry * ent = (void *) (base + GET_CP_FUNC_ENTRY());

    if (ent->phandle && !ent->phandle && ent->uri) {
        /* XXX: reopen the stream */
    }
}
END_RS_FUNC(palhdl)

BEGIN_CP_FUNC(migratable)
{
    struct shim_mem_entry * mem_entry;

    DO_CP_SIZE(memory, &__migratable, &__migratable_end - &__migratable,
               &mem_entry);

    struct shim_cp_entry * entry = ADD_CP_FUNC_ENTRY(0);
    mem_entry->paddr = (void **) &entry->cp_un.cp_val;
}
END_CP_FUNC(migratable)

BEGIN_RS_FUNC(migratable)
{
    void * data = (void *) GET_CP_FUNC_ENTRY();
    CP_REBASE(data);
    memcpy(&__migratable, data, &__migratable_end - &__migratable);
}
END_RS_FUNC(migratable)

BEGIN_CP_FUNC(environ)
{
    const char ** e, ** envp = (void *) obj;
    int nenvp = 0;
    int envp_bytes = 0;

    for (e = envp ; *e ; e++) {
        nenvp++;
        envp_bytes += strlen(*e) + 1;
    }

    ptr_t off = ADD_CP_OFFSET(sizeof(char *) * (nenvp + 1) + envp_bytes);
    const char ** new_envp = (void *) base + off;
    char * ptr = (void *) base + off + sizeof(char *) * (nenvp + 1);

    for (int i = 0 ; i < nenvp ; i++) {
        int len = strlen(envp[i]);
        new_envp[i] = ptr;
        memcpy(ptr, envp[i], len + 1);
        ptr += len + 1;
    }

    new_envp[nenvp] = NULL;
    ADD_CP_FUNC_ENTRY(off);
}
END_CP_FUNC(environ)

BEGIN_RS_FUNC(environ)
{
    const char ** envp = (void *) base + GET_CP_FUNC_ENTRY();
    const char ** e;

    for (e = envp ; *e ; e++) {
        CP_REBASE(*e);
        DEBUG_RS("%s", *e);
    }

    initial_envp = envp;
}
END_RS_FUNC(environ)

BEGIN_CP_FUNC(qstr)
{
    struct shim_qstr * qstr = (struct shim_qstr *) obj;

    if (qstr->len < QSTR_SIZE) {
        if (qstr->oflow) {
            memcpy(qstr->name, qstr->oflow, qstr->len + 1);
            qstr->oflow = NULL;
        }
    } else {
        struct shim_str * str =
            (void *) (base + ADD_CP_OFFSET(qstr->len + 1));
        memcpy(str, qstr->oflow, qstr->len + 1);
        qstr->oflow = str;
        ADD_CP_FUNC_ENTRY((ptr_t) qstr - base);
    }
}
END_CP_FUNC(qstr)

BEGIN_RS_FUNC(qstr)
{
    struct shim_qstr * qstr = (void *) (base + GET_CP_FUNC_ENTRY());
    CP_REBASE(qstr->oflow);
}
END_RS_FUNC(qstr)

BEGIN_CP_FUNC(gipc)
{
    ptr_t off = ADD_CP_OFFSET(sizeof(struct shim_gipc_entry));

    void * send_addr = (void *) ALIGN_DOWN(obj);
    size_t send_size = (void *) ALIGN_UP(obj + size) - send_addr;

    struct shim_gipc_entry * entry = (void *) (base + off);

    entry->mem.addr = send_addr;
    entry->mem.size = send_size;
    entry->mem.prot = PAL_PROT_READ|PAL_PROT_WRITE;
    entry->mem.prev = (void *) store->last_gipc_entry;
    store->last_gipc_entry = entry;
    store->gipc_nentries++;

#if HASH_GIPC == 1
    struct md5_ctx ctx;
    md5_init(&ctx);
    md5_update(&ctx, send_addr, allocsize);
    md5_final(&ctx);
    entry->first_hash = *(unsigned long *) ctx.digest;
#endif /* HASH_GIPC == 1 */

    ADD_CP_FUNC_ENTRY(off);

    if (objp)
        *objp = entry;
}
END_CP_FUNC(gipc)

BEGIN_RS_FUNC(gipc)
{
#if HASH_GIPC == 1
    struct shim_gipc_entry * entry = (void *) (base + GET_CP_FUNC_ENTRY());

    PAL_FLG pal_prot = PAL_PROT(entry->prot, 0);
    if (!(pal_prot & PROT_READ))
        DkVirtualMemoryProtect(entry->addr, entry->npages * allocsize,
                               pal_prot|PAL_PROT_READ);

    struct md5_ctx ctx;
    md5_init(&ctx);
    md5_update(&ctx, entry->addr, allocsize);
    md5_final(&ctx);
    assert(*(unsigned long *) ctx.digest == entry->first_hash);

    if (!(pal_prot & PAL_PROT_READ))
        DkVirtualMemoryProtect(entry->addr, entry->npages * allocsize,
                               pal_prot);
#endif /* HASH_GIPC == 1 */
}
END_RS_FUNC(gipc)

static int send_checkpoint_by_gipc (PAL_HANDLE gipc_store,
                                    struct shim_cp_store * store)
{
    PAL_PTR hdr_addr = (PAL_PTR) store->base;
    PAL_NUM hdr_size = (PAL_NUM) store->offset + store->mem_size;
    assert(ALIGNED(hdr_addr));

    int mem_nentries = store->mem_nentries;

    if (mem_nentries) {
        struct shim_mem_entry ** mem_entries =
                    __alloca(sizeof(struct shim_mem_entry *) * mem_nentries);
        int mem_cnt = mem_nentries;
        struct shim_mem_entry * mem_ent = store->last_mem_entry;

        for (; mem_ent ; mem_ent = mem_ent->prev) {
            if (!mem_cnt)
                return -EINVAL;
            mem_entries[--mem_cnt] = mem_ent;
        }

        mem_entries  += mem_cnt;
        mem_nentries -= mem_cnt;

        for (int i = 0 ; i < mem_nentries ; i++) {
            void * mem_addr = (void *) store->base +
                              __ADD_CP_OFFSET(mem_entries[i]->size);

            assert(store->offset <= hdr_size);
            memcpy(mem_addr, mem_entries[i]->addr, mem_entries[i]->size);
            mem_entries[i]->data = mem_addr;
        }
    }

    hdr_size = ALIGN_UP(hdr_size);
    int npages = DkPhysicalMemoryCommit(gipc_store, 1, &hdr_addr, &hdr_size, 0);
    if (!npages)
        return -EPERM;

    int nentries = store->gipc_nentries;
    PAL_PTR * gipc_addrs = __alloca(sizeof(PAL_PTR) * nentries);
    PAL_NUM * gipc_sizes = __alloca(sizeof(PAL_NUM) * nentries);
    int total_pages = 0;
    int cnt = nentries;
    struct shim_gipc_entry * ent = store->last_gipc_entry;

    for (; ent ; ent = (void *) ent->mem.prev) {
        if (!cnt)
            return -EINVAL;
        cnt--;
        gipc_addrs[cnt] = ent->mem.addr;
        gipc_sizes[cnt] = ent->mem.size;
        total_pages += ent->mem.size / allocsize;
    }

    gipc_addrs += cnt;
    gipc_sizes += cnt;
    nentries   -= cnt;

    /* Chia-Che: sending an empty page can't ever be a smart idea.
       we might rather fail here */
    npages = DkPhysicalMemoryCommit(gipc_store, nentries, gipc_addrs,
                                    gipc_sizes, 0);

    if (npages < total_pages) {
        debug("gipc supposed to send %d pages, but only %d pages sent\n",
              total_pages, npages);
        return -ENOMEM;
    }

    ADD_PROFILE_OCCURENCE(migrate_send_gipc_pages, npages);
    return 0;
}

static int send_checkpoint_on_stream (PAL_HANDLE stream,
                                      struct shim_cp_store * store)
{
    int mem_nentries = store->mem_nentries;
    struct shim_mem_entry ** mem_entries;

    if (mem_nentries) {
        mem_entries = __alloca(sizeof(struct shim_mem_entry *) * mem_nentries);
        int mem_cnt = mem_nentries;
        struct shim_mem_entry * mem_ent = store->last_mem_entry;

        for (; mem_ent ; mem_ent = mem_ent->prev) {
            if (!mem_cnt)
                return -EINVAL;
            mem_entries[--mem_cnt] = mem_ent;
        }

        void * mem_addr = (void *) store->base + store->offset;
        mem_entries  += mem_cnt;
        mem_nentries -= mem_cnt;

        for (int i = 0 ; i < mem_nentries ; i++) {
            int mem_size = mem_entries[i]->size;
            mem_entries[i]->data = mem_addr;
            mem_addr += mem_size;
        }
    }

    size_t total_bytes = store->offset;
    size_t bytes = 0;

    do {
        size_t ret = DkStreamWrite(stream, 0, total_bytes - bytes,
                                   (void *) store->base + bytes, NULL);

        if (!ret)
            return -PAL_ERRNO;

        bytes += ret;
    } while (bytes < total_bytes);

    ADD_PROFILE_OCCURENCE(migrate_send_on_stream, total_bytes);

    for (int i = 0 ; i < mem_nentries ; i++) {
        size_t mem_size = mem_entries[i]->size;
        void * mem_addr = mem_entries[i]->addr;
        bytes = 0;
        do {
            size_t ret = DkStreamWrite(stream, 0, mem_size - bytes,
                                       mem_addr + bytes, NULL);
            if (!ret)
                return -PAL_ERRNO;

            bytes += ret;
        } while (bytes < mem_entries[i]->size);

        if (!(mem_entries[i]->prot & PAL_PROT_READ))
            DkVirtualMemoryProtect(mem_addr, mem_size, mem_entries[i]->prot);

        mem_entries[i]->size = mem_size;
        ADD_PROFILE_OCCURENCE(migrate_send_on_stream, mem_size);
    }

    return 0;
 }


static int restore_gipc (PAL_HANDLE gipc, struct gipc_header * hdr, ptr_t base,
                         long rebase)
{
    struct shim_gipc_entry * gipc_entries = (void *) (base + hdr->entoffset);
    int nentries = hdr->nentries;

    if (!nentries)
        return 0;

    debug("restore memory by gipc: %d entries\n", nentries);

    struct shim_gipc_entry ** entries =
            __alloca(sizeof(struct shim_gipc_entry *) * nentries);

    struct shim_gipc_entry * entry = gipc_entries;
    int cnt = nentries;

    while (entry) {
        CP_REBASE(entry->mem.prev);
        CP_REBASE(entry->mem.paddr);
        if (!cnt)
            return -EINVAL;
        entries[--cnt] = entry;
        entry = (void *) entry->mem.prev;
    }

    entries  += cnt;
    nentries -= cnt;
    PAL_PTR * addrs = __alloca(sizeof(PAL_PTR) * nentries);
    PAL_NUM * sizes = __alloca(sizeof(PAL_NUM) * nentries);
    PAL_FLG * prots = __alloca(sizeof(PAL_FLG) * nentries);

    for (int i = 0 ; i < nentries ; i++) {
        addrs[i] = entries[i]->mem.paddr ? NULL : (PAL_PTR) entries[i]->mem.addr;
        sizes[i] = entries[i]->mem.size;
        prots[i] = entries[i]->mem.prot;
    }

    if (!DkPhysicalMemoryMap(gipc, nentries, addrs, sizes, prots))
        return -PAL_ERRNO;

    for (int i = 0 ; i < nentries ; i++)
        if (entries[i]->mem.paddr)
            *(void **) entries[i]->mem.paddr = (void *) addrs[i];

    return 0;
}

int restore_checkpoint (struct cp_header * cphdr, struct mem_header * memhdr,
                        ptr_t base, int type)
{
    ptr_t cpoffset = cphdr->offset;
    ptr_t * offset = &cpoffset;
    long rebase = base - (ptr_t) cphdr->addr;
    int ret = 0;

    if (type)
        debug("restore checkpoint at %p rebased from %p (%s only)\n",
              base, cphdr->addr, CP_FUNC_NAME(type));
    else
        debug("restore checkpoint at %p rebased from %p\n",
              base, cphdr->addr);

    if (memhdr && memhdr->nentries) {
        struct shim_mem_entry * entry =
                    (void *) (base + memhdr->entoffset);

        for (; entry ; entry = entry->prev) {
            CP_REBASE(entry->prev);
            CP_REBASE(entry->paddr);

            if (entry->paddr) {
                *entry->paddr = entry->data;
            } else {
                debug("memory entry [%p]: %p-%p\n", entry, entry->addr,
                      entry->addr + entry->size);

                PAL_PTR addr = ALIGN_DOWN(entry->addr);
                PAL_NUM size = ALIGN_UP(entry->addr + entry->size) -
                               (void *) addr;
                PAL_FLG prot = entry->prot;

                if (!DkVirtualMemoryAlloc(addr, size, 0, prot|PAL_PROT_WRITE)) {
                    debug("failed allocating %p-%p\n", addr, addr + size);
                    return -PAL_ERRNO;
                }

                CP_REBASE(entry->data);
                memcpy(entry->addr, entry->data, entry->size);

                if (!(entry->prot & PAL_PROT_WRITE) &&
                    !DkVirtualMemoryProtect(addr, size, prot)) {
                    debug("failed protecting %p-%p (ignored)\n", addr, addr + size);
                }
            }
        }
    }

    struct shim_cp_entry * cpent = NEXT_CP_ENTRY();

    while (cpent) {
        if (cpent->cp_type < CP_FUNC_BASE)
            goto next;
        if (type && cpent->cp_type != type)
            goto next;

        rs_func rs = (&__rs_func) [cpent->cp_type - CP_FUNC_BASE];
        ret = (*rs) (cpent, base, offset, rebase);
        if (ret < 0) {
            sys_printf("restore_checkpoint() at %s (%d)\n",
                       CP_FUNC_NAME(cpent->cp_type), ret);
            return ret;
        }
next:
        cpent = NEXT_CP_ENTRY();
    }

    debug("successfully restore checkpoint loaded at %p - %p\n",
          base, base + cphdr->size);

    return 0;
}

int init_from_checkpoint_file (const char * filename,
                               struct newproc_cp_header * hdr,
                               void ** cpptr)
{
    struct shim_dentry * dir = NULL;
    int ret;

    /* XXX: Not sure what to do here yet */
    assert(0);
    ret = path_lookupat(NULL, filename, LOOKUP_ACCESS|LOOKUP_DIRECTORY, &dir, NULL);
    if (ret < 0)
        return ret;

    struct shim_mount * fs = dir->fs;
    struct shim_dirent * dirent;

    if (!fs->d_ops || !fs->d_ops->readdir) {
        ret = -EACCES;
        goto out;
    }

    if ((ret = fs->d_ops->readdir(dir, &dirent)) < 0)
        goto out;

    struct shim_dentry * first = NULL;
    struct shim_dirent * d = dirent;
    for ( ; d ; d = d->next) {
        struct shim_dentry * file;
        if ((ret = lookup_dentry(dir, d->name, strlen(d->name), false,
                                 &file, dir->fs)) < 0)
            continue;
        if (file->state & DENTRY_NEGATIVE)
            continue;

        if (!first) {
            first = file;
            continue;
        }

        const char * argv[3];
        argv[0] = "-resume-file";
        argv[1] = dentry_get_path(file, true, NULL);
        argv[2] = 0;

        PAL_HANDLE proc = DkProcessCreate(NULL, 0, argv);
        if (!proc) {
            ret = -PAL_ERRNO;
            goto out;
        }

        put_dentry(file);
    }

    if (first) {
        ret = restore_from_file(dentry_get_path(first, true, NULL), hdr, cpptr);
        put_dentry(first);
    }

    free(dirent);
out:
    put_dentry(dir);
    return ret;
}

int restore_from_file (const char * filename, struct newproc_cp_header * hdr,
                       void ** cpptr)
{
    struct shim_handle * file = get_new_handle();
    if (!file)
        return -ENOMEM;

    int ret = open_namei(file, NULL, filename, O_RDWR, 0, NULL);
    if (ret < 0) {
        put_handle(file);
        return ret;
    }

    struct shim_mount * fs = file->fs;
    open_handle(file);
    debug("restore %s\n", filename);

    struct cp_header cphdr;
    ret = fs->fs_ops->read(file, &cphdr, sizeof(struct cp_header));
    if (ret < 0)
        goto out;

    void * cpaddr = cphdr.addr;
    ret = fs->fs_ops->mmap(file, &cpaddr, ALIGN_UP(cphdr.size),
                           PROT_READ|PROT_WRITE,
                           MAP_PRIVATE|MAP_FILE, 0);
    if (ret < 0)
        goto out;

    hdr->hdr = cphdr;
    *cpptr = cpaddr;
    migrated_memory_start = cpaddr;
    migrated_memory_end = cpaddr + hdr->hdr.size;
out:
    close_handle(file);
    return ret;
}

int send_handles_on_stream (PAL_HANDLE stream, struct shim_cp_store * store)
{
    int nentries = store->palhdl_nentries;
    if (!nentries)
        return 0;

    struct shim_palhdl_entry ** entries =
            __alloca(sizeof(struct shim_palhdl_entry *) * nentries);

    struct shim_palhdl_entry * entry = store->last_palhdl_entry;
    int cnt = nentries;

    for ( ; entry ; entry = entry->prev)
        if (entry->handle) {
            if (!cnt)
                return -EINVAL;
            entries[--cnt] = entry;
        }

    entries  += cnt;
    nentries -= cnt;

    for (int i = 0 ; i < nentries ; i++)
        if (!DkSendHandle(stream, entries[i]->handle))
            entries[i]->handle = NULL;

    return 0;
}

int receive_handles_on_stream (struct palhdl_header * hdr, ptr_t base,
                               long rebase)
{
    struct shim_palhdl_entry * palhdl_entries =
                            (void *) (base + hdr->entoffset);
    int nentries = hdr->nentries;

    if (!nentries)
        return 0;

    debug("receive handles: %d entries\n", nentries);

    struct shim_palhdl_entry ** entries =
            __alloca(sizeof(struct shim_palhdl_entry *) * nentries);

    struct shim_palhdl_entry * entry = palhdl_entries;
    int cnt = nentries;

    for ( ; entry ; entry = entry->prev) {
        CP_REBASE(entry->prev);
        CP_REBASE(entry->phandle);
        if (!cnt)
            return -EINVAL;
        entries[--cnt] = entry;
    }

    entries  += cnt;
    nentries -= cnt;

    for (int i = 0 ; i < nentries ; i++) {
        entry = entries[i];
        if (entry->handle) {
            PAL_HANDLE hdl = DkReceiveHandle(PAL_CB(parent_process));
            if (hdl) {
                *entry->phandle = hdl;
                continue;
            }
        }
    }

    return 0;
}

static void * cp_alloc (struct shim_cp_store * store, void * addr, size_t size)
{
    if (addr) {
        /*
         * If the checkpoint needs more space, try to extend the checkpoint
         * store at the current address.
         */
        debug("try extend checkpoint store: %p-%p (size = %ld)\n",
              addr, addr + size, size);

        if (bkeep_mmap(addr, size, PROT_READ|PROT_WRITE, CP_VMA_FLAGS,
                       NULL, 0, "cpstore") < 0)
            return NULL;
    } else {
        /*
         * Here we use a strategy to reduce internal fragmentation of virtual
         * memory space. Because we need a relatively large, continuous space
         * for dumping the checkpoint data, internal fragmentation can cause
         * the process to drain the virtual address space after forking a few
         * times. The previous space used for checkpoint may be fragmented
         * at the next fork.
         *
         * A simple trick we use here is to reserve some space right after the
         * checkpoint space. The reserved space is half of the size of the
         * checkpoint space, but can be further fine-tuned.
         */
        size_t reserve_size = ALIGN_UP(size >> 1);

        debug("try allocate checkpoint store (size = %ld, reserve = %ld)\n",
              size, reserve_size);

        /*
         * Allocating the checkpoint space at the first space found from the
         * top of the virtual address space.
         */
        addr = bkeep_unmapped_any(size + reserve_size, PROT_READ|PROT_WRITE,
                                  CP_VMA_FLAGS, NULL, 0, "cpstore");
        if (!addr)
            return NULL;

        bkeep_munmap(addr + size, reserve_size, CP_VMA_FLAGS);
    }

    addr = (void *) DkVirtualMemoryAlloc(addr, size, 0,
                                         PAL_PROT_READ|PAL_PROT_WRITE);
    if (!addr)
        bkeep_munmap(addr, size, CP_VMA_FLAGS);

    return addr;
}

DEFINE_PROFILE_CATAGORY(migrate_proc, migrate);
DEFINE_PROFILE_INTERVAL(migrate_create_process,   migrate_proc);
DEFINE_PROFILE_INTERVAL(migrate_create_gipc,      migrate_proc);
DEFINE_PROFILE_INTERVAL(migrate_connect_ipc,      migrate_proc);
DEFINE_PROFILE_INTERVAL(migrate_init_checkpoint,  migrate_proc);
DEFINE_PROFILE_INTERVAL(migrate_save_checkpoint,  migrate_proc);
DEFINE_PROFILE_INTERVAL(migrate_send_header,      migrate_proc);
DEFINE_PROFILE_INTERVAL(migrate_send_checkpoint,  migrate_proc);
DEFINE_PROFILE_OCCURENCE(migrate_send_on_stream,  migrate_proc);
DEFINE_PROFILE_OCCURENCE(migrate_send_gipc_pages, migrate_proc);
DEFINE_PROFILE_INTERVAL(migrate_send_pal_handles, migrate_proc);
DEFINE_PROFILE_INTERVAL(migrate_free_checkpoint,  migrate_proc);
DEFINE_PROFILE_INTERVAL(migrate_wait_response,    migrate_proc);

static bool warn_no_gipc __attribute_migratable = true;

/*
 * Create a new process and migrate the process states to the new process.
 *
 * @migrate: migration function defined by the caller
 * @exec: the executable to load in the new process
 * @argv: arguments passed to the new process
 * @thread: thread handle to be migrated to the new process
 *
 * The remaining arguments are passed into the migration function.
 */
int do_migrate_process (int (*migrate) (struct shim_cp_store *,
                                        struct shim_thread *,
                                        struct shim_process *, va_list),
                        struct shim_handle * exec,
                        const char ** argv,
                        struct shim_thread * thread, ...)
{
    int ret = 0;
    struct shim_process * new_process = NULL;
    struct newproc_header hdr;
    struct shim_cp_store * cpstore = NULL;
    int bytes;
    memset(&hdr, 0, sizeof(hdr));

#ifdef PROFILE
    unsigned long begin_create_time = GET_PROFILE_INTERVAL();
    unsigned long create_time = begin_create_time;
#endif
    BEGIN_PROFILE_INTERVAL();

    /*
     * Create the process first. The new process requires some time
     * to initialize before starting to receive checkpoint data.
     * Parallizing the process creation and checkpointing can improve
     * the latency of forking.
     */
    PAL_HANDLE proc = DkProcessCreate(exec ? qstrgetstr(&exec->uri) :
                                      pal_control.executable,
                                      0, argv);

    if (!proc) {
        ret = -PAL_ERRNO;
        goto err;
    }

    SAVE_PROFILE_INTERVAL(migrate_create_process);

    /*
     * Detect if GIPC is supported by the host. If GIPC is not supported
     * forking may be slow because we have to use RPC streams for migrating
     * user memory.
     */
    bool use_gipc = false;
    PAL_NUM gipc_key;
    PAL_HANDLE gipc_hdl = DkCreatePhysicalMemoryChannel(&gipc_key);

    if (gipc_hdl) {
        debug("created gipc store: gipc:%lu\n", gipc_key);
        use_gipc = true;
        SAVE_PROFILE_INTERVAL(migrate_create_gipc);
    } else {
        if (warn_no_gipc) {
            warn_no_gipc = false;
            sys_printf("WARNING: no physical memory support, process creation "
                       "may be slow.\n");
        }
    }

    /* Create process and IPC bookkeepings */
    if (!(new_process = create_new_process(true))) {
        ret = -ENOMEM;
        goto err;
    }

    if (!(new_process->self = create_ipc_port(0, false))) {
        ret = -EACCES;
        goto err;
    }

    SAVE_PROFILE_INTERVAL(migrate_connect_ipc);

    /* Allocate a space for dumping the checkpoint data. */
    cpstore = __alloca(sizeof(struct shim_cp_store));
    memset(cpstore, 0, sizeof(struct shim_cp_store));
    cpstore->alloc    = cp_alloc;
    cpstore->use_gipc = use_gipc;
    cpstore->bound    = CP_INIT_VMA_SIZE;

    while (1) {
        /*
         * Try allocating a space of a certain size. If the allocation fails,
         * continue to try with smaller sizes.
         */
        cpstore->base = (ptr_t) cp_alloc(cpstore, 0, cpstore->bound);
        if (cpstore->base)
            break;

        cpstore->bound >>= 1;
        if (cpstore->bound < allocsize)
            break;
    }

    if (!cpstore->base) {
        ret = -ENOMEM;
        debug("failed creating checkpoint store\n");
        goto err;
    }

    SAVE_PROFILE_INTERVAL(migrate_init_checkpoint);

    /* Calling the migration function defined by the caller. */
    va_list ap;
    va_start(ap, thread);
    ret = (*migrate) (cpstore, thread, new_process, ap);
    va_end(ap);
    if (ret < 0) {
        debug("failed creating checkpoint (ret = %d)\n", ret);
        goto err;
    }

    SAVE_PROFILE_INTERVAL(migrate_save_checkpoint);

    unsigned long checkpoint_time = GET_PROFILE_INTERVAL();
    unsigned long checkpoint_size = cpstore->offset + cpstore->mem_size;

    /* Checkpoint data created. */
    debug("checkpoint of %u bytes created, %lu microsecond is spent.\n",
          checkpoint_size, checkpoint_time);

    hdr.checkpoint.hdr.addr = (void *) cpstore->base;
    hdr.checkpoint.hdr.size = checkpoint_size;

    if (cpstore->mem_nentries) {
        hdr.checkpoint.mem.entoffset =
                    (ptr_t) cpstore->last_mem_entry - cpstore->base;
        hdr.checkpoint.mem.nentries  = cpstore->mem_nentries;
    }

    if (cpstore->use_gipc) {
        snprintf(hdr.checkpoint.gipc.uri, sizeof(hdr.checkpoint.gipc.uri),
                 "gipc:%lld", gipc_key);

        if (cpstore->gipc_nentries) {
            hdr.checkpoint.gipc.entoffset =
                        (ptr_t) cpstore->last_gipc_entry - cpstore->base;
            hdr.checkpoint.gipc.nentries  = cpstore->gipc_nentries;
        }
    }

    if (cpstore->palhdl_nentries) {
        hdr.checkpoint.palhdl.entoffset =
                    (ptr_t) cpstore->last_palhdl_entry - cpstore->base;
        hdr.checkpoint.palhdl.nentries  = cpstore->palhdl_nentries;
    }

#ifdef PROFILE
    hdr.begin_create_time  = begin_create_time;
    hdr.create_time = create_time;
    hdr.write_proc_time = GET_PROFILE_INTERVAL();
#endif

    /*
     * Sending a header to the new process through the RPC stream to
     * notify the process to start receiving the checkpoint.
     */
    bytes = DkStreamWrite(proc, 0, sizeof(struct newproc_header), &hdr, NULL);
    if (!bytes) {
        ret = -PAL_ERRNO;
        debug("failed writing to process stream (ret = %d)\n", ret);
        goto err;
    } else if (bytes < sizeof(struct newproc_header)) {
        ret = -EACCES;
        goto err;
    }

    ADD_PROFILE_OCCURENCE(migrate_send_on_stream, bytes);
    SAVE_PROFILE_INTERVAL(migrate_send_header);

    /* Sending the checkpoint either through GIPC or the RPC stream */
    ret = cpstore->use_gipc ? send_checkpoint_by_gipc(gipc_hdl, cpstore) :
          send_checkpoint_on_stream(proc, cpstore);

    if (ret < 0) {
        debug("failed sending checkpoint (ret = %d)\n", ret);
        goto err;
    }

    SAVE_PROFILE_INTERVAL(migrate_send_checkpoint);

    /*
     * For socket and RPC streams, we need to migrate the PAL handles
     * to the new process using PAL calls.
     */
    if ((ret = send_handles_on_stream(proc, cpstore)) < 0)
        goto err;

    SAVE_PROFILE_INTERVAL(migrate_send_pal_handles);

    /* Free the checkpoint space */
    if ((ret = bkeep_munmap((void *) cpstore->base, cpstore->bound,
                            CP_VMA_FLAGS)) < 0) {
        debug("failed unmaping checkpoint (ret = %d)\n", ret);
        goto err;
    }

    DkVirtualMemoryFree((PAL_PTR) cpstore->base, cpstore->bound);

    SAVE_PROFILE_INTERVAL(migrate_free_checkpoint);

    /* Wait for the response from the new process */
    struct newproc_response res;
    bytes = DkStreamRead(proc, 0, sizeof(struct newproc_response), &res,
                         NULL, 0);
    if (bytes == 0) {
        ret = -PAL_ERRNO;
        goto err;
    }

    SAVE_PROFILE_INTERVAL(migrate_wait_response);

    if (gipc_hdl)
        DkObjectClose(gipc_hdl);

    /* Notify the namespace manager regarding the subleasing of TID */
    ipc_pid_sublease_send(res.child_vmid, thread->tid,
                          qstrgetstr(&new_process->self->uri),
                          NULL);

    /* Listen on the RPC stream to the new process */
    add_ipc_port_by_id(res.child_vmid, proc,
                       IPC_PORT_DIRCLD|IPC_PORT_LISTEN|IPC_PORT_KEEPALIVE,
                       &ipc_child_exit,
                       NULL);

    destroy_process(new_process);
    return 0;
err:
    if (gipc_hdl)
        DkObjectClose(gipc_hdl);
    if (proc)
        DkObjectClose(proc);
    if (new_process)
        destroy_process(new_process);

    sys_printf("process creation failed\n");
    return ret;
}

/*
 * Loading the checkpoint from the parent process or a checkpoint file
 *
 * @hdr: checkpoint header
 * @cpptr: returning the pointer of the loaded checkpoint
 */
int do_migration (struct newproc_cp_header * hdr, void ** cpptr)
{
    void * base = NULL;
    size_t size = hdr->hdr.size;
    PAL_PTR mapaddr;
    PAL_NUM mapsize;
    long rebase;
    bool use_gipc = !!hdr->gipc.uri[0];
    PAL_HANDLE gipc_store;
    int ret = 0;
    BEGIN_PROFILE_INTERVAL();

    /*
     * Allocate a large enough space to load the checkpoint data.
     *
     * If CPSTORE_DERANDOMIZATION is enabled, try to allocate the space
     * at the exact address where the checkpoint is created. Otherwise,
     * just allocate at the first space we found from the top of the virtual
     * memory space.
     */

#if CPSTORE_DERANDOMIZATION == 1
    if (hdr->hdr.addr
        && lookup_overlap_vma(hdr->hdr.addr, size, NULL) == -ENOENT) {

        /* Try to load the checkpoint at the same address */
        base = hdr->hdr.addr;
        mapaddr = (PAL_PTR) ALIGN_DOWN(base);
        mapsize = (PAL_PTR) ALIGN_UP(base + size) - mapaddr;

        /* Need to create VMA before allocation */
        ret = bkeep_mmap((void *) mapaddr, mapsize,
                         PROT_READ|PROT_WRITE, CP_VMA_FLAGS,
                         NULL, 0, "cpstore");
        if (ret < 0)
            base = NULL;
    }
#endif

    if (!base) {
        base = bkeep_unmapped_any(ALIGN_UP(size),
                                  PROT_READ|PROT_WRITE, CP_VMA_FLAGS,
                                  NULL, 0, "cpstore");
        if (!base)
            return -ENOMEM;

        mapaddr = (PAL_PTR) base;
        mapsize = (PAL_NUM) ALIGN_UP(size);
    }

    debug("checkpoint mapped at %p-%p\n", base, base + size);

    PAL_FLG pal_prot = PAL_PROT_READ|PAL_PROT_WRITE;
    PAL_PTR mapped = mapaddr;

    if (use_gipc) {
        debug("open gipc store: %s\n", hdr->gipc.uri);

        gipc_store = DkStreamOpen(hdr->gipc.uri, 0, 0, 0, 0);
        if (!gipc_store ||
            !DkPhysicalMemoryMap(gipc_store, 1, &mapped, &mapsize, &pal_prot))
            return -PAL_ERRNO;

        SAVE_PROFILE_INTERVAL(child_load_checkpoint_by_gipc);
    } else {
        void * mapped = DkVirtualMemoryAlloc(mapaddr, mapsize, 0, pal_prot);
        if (!mapped)
            return -PAL_ERRNO;
    }

    assert(mapaddr == mapped);
    /*
     * If the checkpoint is loaded at a different address from where it is
     * created, we need to rebase the pointers in the checkpoint.
     */
    rebase = (long) ((uintptr_t) base - (uintptr_t) hdr->hdr.addr);

    /* Load the memory data sent separately over GIPC or the RPC stream. */
    if (use_gipc) {
        if ((ret = restore_gipc(gipc_store, &hdr->gipc, (ptr_t) base, rebase)) < 0)
            return ret;

        SAVE_PROFILE_INTERVAL(child_load_memory_by_gipc);
        DkStreamDelete(gipc_store, 0);
    } else {
        int total_bytes = 0;
        while (total_bytes < size) {
            int bytes = DkStreamRead(PAL_CB(parent_process), 0,
                                     size - total_bytes,
                                     (void *) base + total_bytes, NULL, 0);

            if (!bytes)
                return -PAL_ERRNO;

            total_bytes += bytes;
        }

        SAVE_PROFILE_INTERVAL(child_load_checkpoint_on_pipe);
        debug("%d bytes read on stream\n", total_bytes);
    }

    /* Receive socket or RPC handles from the parent process. */
    ret = receive_handles_on_stream(&hdr->palhdl, (ptr_t) base, rebase);
    if (ret < 0) {
        /* TODO: unload the checkpoint space */
        return ret;
    }

    SAVE_PROFILE_INTERVAL(child_receive_handles);

    migrated_memory_start = (void *) mapaddr;
    migrated_memory_end = (void *) mapaddr + mapsize;
    *cpptr = (void *) base;
    return 0;
}

void restore_context (struct shim_context * context)
{
    int nregs = sizeof(struct shim_regs) / sizeof(void *);
    void * regs[nregs + 1];

    if (context->regs)
        memcpy(regs, context->regs, sizeof(struct shim_regs));
    else
        memset(regs, 0, sizeof(struct shim_regs));

    debug("restore context: SP = %p, IP = %p\n", context->sp, context->ret_ip);

    regs[nregs] = (void *) context->sp - 8;
    *(void **) (context->sp - 8) = context->ret_ip;

    /* Ready to resume execution, re-enable preemption. */
    shim_tcb_t * tcb = SHIM_GET_TLS();
    __enable_preempt(tcb);

    memset(context, 0, sizeof(struct shim_context));

    asm volatile("movq %0, %%rsp\r\n"
                 "popq %%r15\r\n"
                 "popq %%r14\r\n"
                 "popq %%r13\r\n"
                 "popq %%r12\r\n"
                 "popq %%r11\r\n"
                 "popq %%r10\r\n"
                 "popq %%r9\r\n"
                 "popq %%r8\r\n"
                 "popq %%rcx\r\n"
                 "popq %%rdx\r\n"
                 "popq %%rsi\r\n"
                 "popq %%rdi\r\n"
                 "popq %%rbx\r\n"
                 "popq %%rbp\r\n"
                 "popq %%rsp\r\n"
                 "movq $0, %%rax\r\n"
                 "retq\r\n"
                 :: "g"(&regs) : "memory");
}
