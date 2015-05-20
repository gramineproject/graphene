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
#include <linux_list.h>

#include <stdarg.h>
#include <asm/fcntl.h>
#include <asm/mman.h>

DEFINE_PROFILE_CATAGORY(migrate_func, );
DEFINE_PROFILE_CATAGORY(resume_func, );

DEFINE_PROFILE_CATAGORY(checkpoint, );
DEFINE_PROFILE_INTERVAL(checkpoint_predict_size, checkpoint);
DEFINE_PROFILE_INTERVAL(checkpoint_alloc_memory, checkpoint);
DEFINE_PROFILE_INTERVAL(checkpoint_copy_object, checkpoint);
DEFINE_PROFILE_INTERVAL(checkpoint_destroy_addr_map, checkpoint);

DEFINE_PROFILE_OCCURENCE(checkpoint_count, checkpoint);
DEFINE_PROFILE_OCCURENCE(checkpoint_total_size, checkpoint);

#define MAP_RANGE_SIZE (0x4000)
#define MAP_RANGE_MASK (~0x3fff)

#define ADDR_HASH_SIZE 4096
#define ADDR_HASH_MASK (0xfff)

#define HASH_POINTER(addr) ((hashfunc((ptr_t)(addr))) & ADDR_HASH_MASK)
#define HASH_POINTER_ALIGNED(addr)  \
                (HASH_POINTER((ptr_t)(addr) & MAP_RANGE_MASK))

typedef uint16_t FASTHASHTYPE;

#define ADDR_MAP_ENTRY_NUM 64

struct addr_map_entry
{
    struct hlist_node hlist;
    struct shim_addr_map map;
};

struct addr_map_buffer {
    struct addr_map_buffer * next;
    size_t num, cnt;
    struct addr_map_entry entries[0];
};

struct migrate_addr_map {
    struct addr_map_buffer * buffer;

    struct hash_map {
        struct hlist_head head[ADDR_HASH_SIZE];
    } addr_map;
};

void * create_addr_map (void)
{
    size_t size_map = sizeof(struct migrate_addr_map);
    void * data = malloc(size_map +
                         sizeof(struct addr_map_buffer) +
                         sizeof(struct addr_map_entry) *
                         ADDR_MAP_ENTRY_NUM);
    if (data == NULL)
        return NULL;

    struct migrate_addr_map *map = (struct migrate_addr_map *) data;
    struct addr_map_buffer *buffer =
                    (struct addr_map_buffer *) (data + size_map);
    memset(map, 0, size_map);
    map->buffer = buffer;
    buffer->next = NULL;
    buffer->num = ADDR_MAP_ENTRY_NUM;
    buffer->cnt = 0;

    return (void *) map;
}

void destroy_addr_map (void * map)
{
    struct migrate_addr_map * m = (struct migrate_addr_map *) map;
    struct addr_map_buffer * buffer = m->buffer, * next;

    for (next = buffer ? buffer->next : NULL ;
         buffer && next ;
         buffer = next, next = next ? next->next : NULL)
        free(buffer);

    free(m);
}

static inline
struct addr_map_buffer * extend_addr_map (struct migrate_addr_map * map)
{
    struct addr_map_buffer *buffer =
                malloc(sizeof(struct addr_map_buffer) +
                       sizeof(struct addr_map_entry) * ADDR_MAP_ENTRY_NUM);

    if (buffer == NULL)
        return NULL;

    buffer->next = map->buffer;
    map->buffer = buffer;
    buffer->num = ADDR_MAP_ENTRY_NUM;
    buffer->cnt = 0;

    return buffer;
}

struct shim_addr_map *
get_addr_map_entry (void * map, ptr_t addr, size_t size, bool create)
{
    struct migrate_addr_map *m = (struct migrate_addr_map *) map;

    FASTHASHTYPE hash = HASH_POINTER(addr);
    struct hlist_head *head = &m->addr_map.head[hash];

    struct addr_map_entry *tmp;
    struct hlist_node *pos;

    struct shim_addr_map * e = NULL;

    hlist_for_each_entry(tmp, pos, head, hlist)
        if (tmp->map.addr == addr)
            e = &tmp->map;

    if (create && !e) {
        struct addr_map_buffer *buffer = m->buffer;

        if (buffer->cnt == buffer->num)
            buffer = extend_addr_map (m);

        struct addr_map_entry *new = &buffer->entries[buffer->cnt++];
        INIT_HLIST_NODE(&new->hlist);
        hlist_add_head(&new->hlist, head);

        new->map.offset = MAP_UNALLOCATED;
        new->map.addr = addr;
        new->map.size = size;
        e = &new->map;
    }

    return e;
}

DEFINE_MIGRATE_FUNC(memory)

MIGRATE_FUNC_BODY(memory)
{
    struct migrate_addr_map * map =
                (struct migrate_addr_map *) store->addr_map;
    ptr_t addr = (ptr_t) obj;

    /* set the offset to 0, so the memory area will not be added to
       range map (if there is one) */
    struct shim_addr_map * e = get_addr_map_entry(map, addr, size, 1);

    ptr_t off = e->offset;

    if (dry) {
        if (off & MAP_UNALLOCATED)
            e->offset = MAP_UNASSIGNED;
        else
            off = 0;
    }

    struct shim_mem_entry * entry = NULL;

    if (off & MAP_UNUSABLE) {
        off = ADD_OFFSET(size);
        void * data = dry ? NULL : (void *) base + off;
        ptr_t entry_off = ADD_OFFSET(sizeof(struct shim_gipc_entry));

        if (!dry) {
            memcpy(data, obj, size);

            entry = (struct shim_mem_entry *) (base + entry_off);
            entry->addr = (void *) addr;
            entry->size = size;
            entry->data = data;
            entry->prot = PROT_READ|PROT_WRITE;
            entry->need_alloc = entry->need_prot = true;
            entry->vma  = NULL;
        }

        ADD_FUNC_ENTRY(entry_off);
    }

    if (!dry && recursive) {
        ptr_t p = (ptr_t) (base + off);

        /* align p to pointer */
        if (p & (sizeof(ptr_t) - 1))
            p = (p + sizeof(ptr_t) - 1) & ~(sizeof(ptr_t) - 1);

        while (p < addr + size) {
            ptr_t val = *(ptr_t *) p;
            struct shim_addr_map * e = get_addr_map_entry (map, val, 0, 0);

            if (e)
                *(ptr_t *) p = base + e->offset + (val - e->addr);

            p += sizeof(ptr_t);
        }
    }

    if (entry && objp)
        *objp = (void *) entry;
}
END_MIGRATE_FUNC

RESUME_FUNC_BODY(memory)
{
    unsigned long off = GET_FUNC_ENTRY();
    struct shim_mem_entry * entry =
                (struct shim_mem_entry *) (base + off);

    RESUME_REBASE(entry->data);
    RESUME_REBASE(entry->vma);

#ifdef DEBUG_RESUME
    debug("dump: %p - %p copied to %p - %p\n",
          entry->data, entry->data + entry->size,
          entry->addr, entry->addr + entry->size);
#endif

    PAL_PTR mapaddr = ALIGN_DOWN(entry->addr);
    PAL_NUM mapsize = ALIGN_UP(entry->addr + entry->size) - mapaddr;
    int pal_prot = PAL_PROT(entry->prot, 0);

    if (entry->need_alloc &&
        !DkVirtualMemoryAlloc(mapaddr, mapsize, 0,
                              pal_prot|PAL_PROT_READ|PAL_PROT_WRITE))
        return -PAL_ERRNO;

    if (entry->need_prot &&
        !DkVirtualMemoryProtect(mapaddr, mapsize,
                                pal_prot|PAL_PROT_READ|PAL_PROT_WRITE))
        return -PAL_ERRNO;

    memcpy(entry->addr, entry->data, entry->size);

    if (entry->vma)
        entry->vma->received = (entry->addr + entry->size) - entry->vma->addr;

    if ((entry->need_alloc || entry->need_prot) &&
        (pal_prot & (PAL_PROT_READ|PAL_PROT_WRITE)) !=
        (PAL_PROT_READ|PAL_PROT_WRITE))
        DkVirtualMemoryProtect(mapaddr, mapsize, pal_prot);
}
END_RESUME_FUNC

DEFINE_MIGRATE_FUNC(migratable)

MIGRATE_FUNC_BODY(migratable)
{
    size = &__migratable_end - &__migratable;

    unsigned long off = ADD_OFFSET(size);
    ADD_FUNC_ENTRY(*offset);
    ADD_ENTRY(ADDR, &__migratable);
    ADD_ENTRY(SIZE, size);

    if (!dry)
        memcpy((void *) (base + off), &__migratable, size);
}
END_MIGRATE_FUNC

RESUME_FUNC_BODY(migratable)
{
    ptr_t off = GET_FUNC_ENTRY();
    GET_ENTRY(ADDR);
    size_t size = GET_ENTRY(SIZE);

#ifdef DEBUG_RESUME
    debug("dump (migratable): %p - %p copied to %p - %p\n", off, off + size,
          &__migratable, &__migratable + size);
#endif

    memcpy((void *) &__migratable, (void *) (base + off), size);
}
END_RESUME_FUNC

DEFINE_MIGRATE_FUNC(environ)

MIGRATE_FUNC_BODY(environ)
{
    void * mem = ALIGN_DOWN(obj);
    size_t memsize = ALIGN_UP(obj + size) - mem;

    ADD_FUNC_ENTRY(obj);

    if (store->use_gipc)
        DO_MIGRATE_SIZE(gipc, mem, memsize, NULL, false);
    else
        DO_MIGRATE_SIZE(memory, mem, memsize, NULL, false);
}
END_MIGRATE_FUNC

RESUME_FUNC_BODY(environ)
{
    initial_envp = (const char **) GET_FUNC_ENTRY() ? : initial_envp;
}
END_RESUME_FUNC

DEFINE_MIGRATE_FUNC(qstr)

MIGRATE_FUNC_BODY(qstr)
{
    struct shim_qstr * qstr = (struct shim_qstr *) obj;

    if (qstr->len < QSTR_SIZE) {
        if (!dry && qstr->oflow) {
            memcpy(qstr->name, qstr->oflow, qstr->len + 1);
            qstr->oflow = NULL;
        }
    } else {
        unsigned long off = ADD_OFFSET(sizeof(struct shim_str));
        ADD_FUNC_ENTRY(qstr - base);

        if (!dry) {
            struct shim_str * str = (struct shim_str *) (base + off);
            memcpy(str, qstr->oflow, qstr->len + 1);
            qstr->oflow = str;
        }
    }
}
END_MIGRATE_FUNC

RESUME_FUNC_BODY(qstr)
{
    struct shim_qstr * qstr = (struct shim_qstr *) (base + GET_FUNC_ENTRY());
    assert(qstr->oflow);
    RESUME_REBASE(qstr->oflow);
}
END_RESUME_FUNC

DEFINE_MIGRATE_FUNC(gipc)

MIGRATE_FUNC_BODY(gipc)
{
    void * send_addr = (void *) ALIGN_DOWN(obj);
    size_t send_size = (void *) ALIGN_UP(obj + size) - send_addr;

    unsigned long off = ADD_OFFSET(sizeof(struct shim_gipc_entry));
    ADD_FUNC_ENTRY(off);

    if (!dry) {
        struct shim_gipc_entry * entry = (void *) (base + off);
        entry->addr_type = ABS_ADDR;
        entry->addr   = send_addr;
        entry->npages = send_size / allocsize;
        entry->prot   = PROT_READ|PROT_WRITE;
        entry->vma    = NULL;
        entry->next   = NULL;

#if HASH_GIPC == 1
        struct md5_ctx ctx;
        md5_init(&ctx);
        md5_update(&ctx, send_addr, allocsize);
        md5_final(&ctx);
        entry->first_hash = *(unsigned long *) ctx.digest;
#endif /* HASH_GIPC == 1 */

        if (!store->gipc_entries)
            store->gipc_entries = entry;
        if (store->gipc_entries_tail)
            store->gipc_entries_tail->next = entry;
        store->gipc_entries_tail = entry;
        store->gipc_nentries++;

        if (objp)
            *objp = entry;
    }
}
END_MIGRATE_FUNC

RESUME_FUNC_BODY(gipc)
{
    unsigned long off = GET_FUNC_ENTRY();
    struct shim_gipc_entry * entry =
                (struct shim_gipc_entry *) (base + off);

    RESUME_REBASE(entry->vma);

#if HASH_GIPC == 1
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
END_RESUME_FUNC

int send_checkpoint_by_gipc (PAL_HANDLE gipc_store,
                             struct shim_cp_store * cpstore)
{
    PAL_PTR hdr_addr = cpstore->cpaddr;
    PAL_NUM hdr_size = ALIGN_UP(cpstore->cpsize);
    assert(ALIGNED(hdr_addr));

    int npages = DkPhysicalMemoryCommit(gipc_store, 1, &hdr_addr, &hdr_size, 0);
    if (!npages)
        return -EPERM;

    int nentries = cpstore->gipc_nentries;
    PAL_PTR * gipc_addrs = __alloca(sizeof(PAL_BUF) * nentries);
    PAL_NUM * gipc_sizes = __alloca(sizeof(PAL_NUM) * nentries);
    int total_pages = 0;
    int cnt = 0;
    struct shim_gipc_entry * ent = cpstore->gipc_entries;

    for ( ; ent ; ent = ent->next, cnt++) {
        switch(ent->addr_type) {
            case ABS_ADDR:
            case ANY_ADDR:
                gipc_addrs[cnt] = ent->addr;
                break;
            case REL_ADDR:
                gipc_addrs[cnt] = (void *) &__load_address + (unsigned long) ent->addr;
                break;
        }
        gipc_sizes[cnt] = allocsize * ent->npages;
        total_pages += ent->npages;
#if 0
        debug("gipc bulk send for %p - %p (%d pages)\n",
              gipc_addrs[cnt], gipc_addrs[cnt] + gipc_sizes[cnt], ent->npages);
#endif

    }

    /* Chia-Che: sending an empty page can't ever be a smart idea.
       we might rather fail here */
    npages = DkPhysicalMemoryCommit(gipc_store, nentries, gipc_addrs,
                                    gipc_sizes, 0);

    if (npages < total_pages) {
        debug("gipc supposed to send %d pages, but only %d pages sent\n",
              total_pages, npages);
        return -ENOMEM;
    }

    return 0;
}

int restore_gipc (PAL_HANDLE gipc, struct gipc_header * hdr, void * cpdata,
                  long cprebase)
{
    struct shim_gipc_entry * gipc_entries =
                (void *) (cpdata + hdr->gipc_entoffset);
    int nentries = hdr->gipc_nentries;

    if (!nentries)
        return 0;

    debug("restore memory by gipc: %d entries\n", nentries);

    PAL_PTR * addrs = __alloca(sizeof(PAL_PTR) * nentries);
    PAL_NUM * sizes = __alloca(sizeof(PAL_NUM) * nentries);
    PAL_FLG * prots = __alloca(sizeof(PAL_FLG) * nentries);

    struct shim_gipc_entry * ent = gipc_entries;
    unsigned long total_pages = 0;

    while (ent) {
        RESUME_REBASE(ent->next);
        ent = ent->next;
    }

    ent = gipc_entries;
    for (int i = 0 ; i < nentries && ent ; i++) {
        switch(ent->addr_type) {
            case ABS_ADDR:
                addrs[i] = ent->addr;
                break;
            case REL_ADDR:
                addrs[i] = (void *) &__load_address + (unsigned long) ent->addr;
                break;
            case ANY_ADDR:
                addrs[i] = NULL;
                break;
        }
        sizes[i] = allocsize * ent->npages;
        prots[i] = ent->prot;
        total_pages += ent->npages;
#if 0
        debug("gipc bulk copy for %p - %p (%d pages)\n", addrs[i],
              addrs[i] + sizes[i], ent->npages);
#endif
        ent = ent->next;
    }

    int received_pages = DkPhysicalMemoryMap(gipc, nentries, addrs, sizes,
                                             prots);
    if (!received_pages)
        return -PAL_ERRNO;

    ent = gipc_entries;
    for (int i = 0 ; i < nentries && ent ; i++) {
        int npages = ent->npages < received_pages ? ent->npages :
                     received_pages;
        received_pages -= npages;

        if (ent->vma) {
            struct shim_vma * vma = ent->vma;
            RESUME_REBASE(vma);
            vma->received = ent->addr + npages * allocsize - vma->addr;
        }

        ent = ent->next;
    }

    return 0;
}

int restore_checkpoint (void * cpaddr, struct cp_header * cphdr, int type)
{
    struct shim_cp_entry * cpent =
                (struct shim_cp_entry *) (cpaddr + cphdr->cpoffset);
    ptr_t cpbase = (ptr_t) (cpaddr + cphdr->cpoffset);
    size_t cplen = cphdr->cpsize;
    long cprebase = cpaddr - cphdr->cpaddr;
    int ret = 0;

    if (type)
        debug("start restoring checkpoint loaded at %p, rebase = %lld "
              "(%s only)\n",
              cpaddr, cprebase, CP_FUNC_NAME(type));
    else
        debug("start restoring checkpoint loaded at %p, rebase = %lld\n",
              cpaddr, cprebase);

    while (cpent->cp_type != CP_NULL) {
        if (cpent->cp_type < CP_FUNC_BASE || (type && cpent->cp_type != type)) {
            cpent++;
            continue;
        }

        struct shim_cp_entry * ent = cpent;
        resume_func resume =
            (&__resume_func) [cpent->cp_type - CP_FUNC_BASE];

        ret = (*resume) (&cpent, cpbase, cplen, cprebase);
        if (ret < 0)
            return ret;

        ent->cp_type = CP_IGNORE;

        if (cpent == ent)
            cpent++;
    }

    debug("successfully restore checkpoint loaded at %p - %p\n",
          cpaddr, cpaddr + cphdr->cpsize);

    return 0;
}

int init_from_checkpoint_file (const char * filename,
                               struct newproc_cp_header * hdr,
                               void ** cpptr)
{
    struct shim_dentry * dir = NULL;
    int ret;

    ret = path_lookupat(NULL, filename, LOOKUP_ACCESS|LOOKUP_DIRECTORY, &dir);
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
                                 &file)) < 0)
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

    void * cpaddr = cphdr.cpaddr;
    ret = fs->fs_ops->mmap(file, &cpaddr, ALIGN_UP(cphdr.cpsize),
                           PROT_READ|PROT_WRITE,
                           MAP_PRIVATE|MAP_FILE, 0);
    if (ret < 0)
        goto out;

    hdr->data = cphdr;
    *cpptr = cpaddr;
    migrated_memory_start = cpaddr;
    migrated_memory_end = cpaddr + hdr->data.cpsize;
out:
    close_handle(file);
    return ret;
}

int send_handles_on_stream (PAL_HANDLE stream, void * cpdata)
{
    struct shim_cp_entry * cpent = cpdata;

    for ( ; cpent->cp_type != CP_NULL ; cpent++)
        if (cpent->cp_type == CP_PALHDL &&
            cpent->cp_un.cp_val) {
            PAL_HANDLE * pal_hdl = cpdata + cpent->cp_un.cp_val;
            assert(*pal_hdl);
            /* Chia-Che: If it fails, we can't handle it, the other side will
               deal with it */
            DkSendHandle(stream, *pal_hdl);
            debug("handle %p sent\n", *pal_hdl);
            *pal_hdl = NULL;
        }

    return 0;
}

int do_migrate_process (int (*migrate) (struct shim_cp_store *,
                                        struct shim_process *,
                                        struct shim_thread *, va_list),
                        struct shim_handle * exec, const char ** argv,
                        struct shim_thread * thread, ...)
{
    int ret = 0;
    struct shim_process * new_process = NULL;
    struct newproc_header hdr;
    struct shim_cp_store * cpstore = NULL;
    int bytes;

#ifdef PROFILE
    unsigned long begin_create_time = GET_PROFILE_INTERVAL();
    unsigned long create_time = begin_create_time;
#endif

    PAL_HANDLE proc = DkProcessCreate(exec ? qstrgetstr(&exec->uri) : NULL,
                                      0, argv);

    if (!proc) {
        ret = -PAL_ERRNO;
        goto err;
    }

    PAL_NUM gipc_key;
    PAL_HANDLE gipc_hdl = DkCreatePhysicalMemoryChannel(&gipc_key);

    if (!gipc_hdl)
        sys_printf("WARNING: no physical memory support, process creation "
                   "will be slow.\n");

    debug("created gipc store: gipc:%lu\n", gipc_key);

    new_process = create_new_process(true);

    if (!new_process) {
        ret = -ENOMEM;
        goto err;
    }

    if (!(new_process->self = create_ipc_port(0, false))) {
        ret = -EACCES;
        goto err;
    }

    cpstore = __alloca(sizeof(struct shim_cp_store));
    INIT_CP_STORE(cpstore);
    cpstore->use_gipc = (!!gipc_hdl);
    va_list ap;
    va_start(ap, thread);
    ret = migrate(cpstore, new_process, thread, ap);
    va_end(ap);
    if (ret < 0)
        goto err;

    unsigned long checkpoint_time = GET_PROFILE_INTERVAL();

    debug("checkpoint of %u bytes created, %lu microsecond is spent.\n",
         cpstore->cpsize, checkpoint_time);

    hdr.checkpoint.data.cpsize = cpstore->cpsize;
    hdr.checkpoint.data.cpaddr = cpstore->cpaddr;
    hdr.checkpoint.data.cpoffset = cpstore->cpdata - cpstore->cpaddr;
    if (gipc_hdl) {
        hdr.checkpoint.gipc.gipc_key = gipc_key;
        hdr.checkpoint.gipc.gipc_entoffset = cpstore->gipc_entries ?
                           (void *) cpstore->gipc_entries - cpstore->cpaddr : 0;
        hdr.checkpoint.gipc.gipc_nentries  = cpstore->gipc_nentries;
    } else {
        hdr.checkpoint.gipc.gipc_key = 0;
        hdr.checkpoint.gipc.gipc_entoffset = 0;
        hdr.checkpoint.gipc.gipc_nentries  = 0;
    }
    hdr.failure = 0;
#ifdef PROFILE
    hdr.begin_create_time  = begin_create_time;
    hdr.create_time = create_time;
    hdr.write_proc_time = GET_PROFILE_INTERVAL();
#endif

    bytes = DkStreamWrite(proc, 0, sizeof(struct newproc_header), &hdr, NULL);
    if (bytes == 0) {
        ret = -PAL_ERRNO;
        goto err;
    }

    if (gipc_hdl) {
        if ((ret = send_checkpoint_by_gipc(gipc_hdl, cpstore)) < 0)
            goto err;
    } else {
        ret = DkStreamWrite(proc, 0, cpstore->cpsize, cpstore->cpdata, NULL);
        if (ret < cpstore->cpsize) {
            ret = -PAL_ERRNO;
            goto err;
        }
    }

    if ((ret = send_handles_on_stream(proc, cpstore->cpdata)) < 0)
        goto err;

    struct newproc_response res;
    bytes = DkStreamRead(proc, 0, sizeof(struct newproc_response), &res,
                         NULL, 0);
    if (bytes == 0) {
        ret = -PAL_ERRNO;
        goto err;
    }

    if (gipc_hdl)
        DkObjectClose(gipc_hdl);

    ipc_pid_sublease_send(res.child_vmid, thread->tid,
                          qstrgetstr(&new_process->self->uri),
                          NULL);

    system_free(cpstore->cpaddr, cpstore->cpsize);

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

DEFINE_PROFILE_INTERVAL(child_load_checkpoint_by_gipc, resume);
DEFINE_PROFILE_INTERVAL(child_load_memory_by_gipc,     resume);
DEFINE_PROFILE_INTERVAL(child_load_checkpoint_on_pipe, resume);
DEFINE_PROFILE_INTERVAL(child_receive_handles,         resume);

int do_migration (struct newproc_cp_header * hdr, void ** cpptr)
{
    void *        cpaddr = hdr->data.cpaddr;
    unsigned long cpsize = hdr->data.cpsize;
    PAL_PTR mapaddr;
    PAL_NUM mapsize;
    unsigned long mapoff;
    int ret = 0;

    debug("checkpoint detected (%d bytes, expected at %p)\n",
          cpsize, cpaddr);

    if (cpaddr &&
        !lookup_overlap_vma(cpaddr, cpsize, NULL)) {
        mapaddr = (PAL_PTR) ALIGN_DOWN(cpaddr);
        mapsize = (PAL_PTR) ALIGN_UP(cpaddr + cpsize) - mapaddr;
        mapoff  = cpaddr - (void *) mapaddr;
    } else {
        mapaddr = (PAL_PTR) 0;
        mapsize = ALIGN_UP(cpsize);
        mapoff  = 0;
    }

    BEGIN_PROFILE_INTERVAL();

    if (hdr->gipc.gipc_key) {
        char gipc_uri[20];
        snprintf(gipc_uri, 20, "gipc:%lu", hdr->gipc.gipc_key);
        debug("open gipc store: %s\n", gipc_uri);

        PAL_FLG mapprot = PAL_PROT_READ|PAL_PROT_WRITE;
        PAL_HANDLE gipc_store = DkStreamOpen(gipc_uri, 0, 0, 0, 0);
        if (!gipc_store ||
            !DkPhysicalMemoryMap(gipc_store, 1, &mapaddr, &mapsize,
                                 &mapprot))
            return -PAL_ERRNO;

        debug("checkpoint loaded at %p\n", cpaddr);

        bkeep_mmap((void *) mapaddr, mapsize,
                   PROT_READ|PROT_WRITE,
                   MAP_PRIVATE|MAP_ANONYMOUS|VMA_INTERNAL,
                   NULL, 0, NULL);

        SAVE_PROFILE_INTERVAL(child_load_checkpoint_by_gipc);

        cpaddr = (void *) mapaddr + mapoff;
        if ((ret = restore_gipc(gipc_store, &hdr->gipc, (void *) cpaddr,
                                (long) cpaddr - (long) hdr->data.cpaddr)) < 0)
            return ret;

        SAVE_PROFILE_INTERVAL(child_load_memory_by_gipc);

        DkStreamDelete(gipc_store, 0);
    } else {
        if (!(mapaddr = DkVirtualMemoryAlloc(mapaddr, mapsize, 0,
                                             PAL_PROT_READ|PAL_PROT_WRITE)))
            return -PAL_ERRNO;

        bkeep_mmap((void *) mapaddr, mapsize,
                   PROT_READ|PROT_WRITE,
                   MAP_PRIVATE|MAP_ANONYMOUS|VMA_INTERNAL,
                   NULL, 0, NULL);

        cpaddr = (void *) mapaddr + mapoff;
        for (int total_bytes = 0 ; total_bytes < cpsize ; ) {
            int bytes = DkStreamRead(PAL_CB(parent_process), 0,
                                     cpsize - total_bytes,
                                     (void *) cpaddr + total_bytes, NULL, 0);

            if (!bytes)
                return -PAL_ERRNO;

            total_bytes += bytes;
        }

        debug("checkpoint loaded at %p\n", cpaddr);

        SAVE_PROFILE_INTERVAL(child_load_checkpoint_on_pipe);
    }

    struct newproc_response res;
    res.child_vmid = cur_process.vmid;
    res.failure = 0;
    int bytes = DkStreamWrite(PAL_CB(parent_process), 0,
                              sizeof(struct newproc_response),
                              &res, NULL);
    if (!bytes)
        return -PAL_ERRNO;

    void * cpdata = (void *) cpaddr + hdr->data.cpoffset;
    struct shim_cp_entry * cpent;
    unsigned long nreceived __attribute__((unused)) = 0;

    for (cpent = cpdata ; cpent->cp_type != CP_NULL ; cpent++)
        if (cpent->cp_type == CP_PALHDL &&
            cpent->cp_un.cp_val) {
            PAL_HANDLE hdl = DkReceiveHandle(PAL_CB(parent_process));
            if (hdl) {
                nreceived++;
                *((PAL_HANDLE *) (cpdata + cpent->cp_un.cp_val)) = hdl;
            }
        }

    SAVE_PROFILE_INTERVAL(child_receive_handles);

    debug("received %ld handles\n", nreceived);

    migrated_memory_start = (void *) cpaddr;
    migrated_memory_end = (void *) cpaddr + hdr->data.cpsize;
    *cpptr = (void *) cpdata;
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

    memset(context, 0, sizeof(struct shim_context));

    asm volatile("movq %0, %%rsp\r\n"
                 "popq %%r15\r\n"
                 "popq %%r14\r\n"
                 "popq %%r13\r\n"
                 "popq %%r12\r\n"
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
