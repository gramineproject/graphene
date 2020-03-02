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

#include "asm-offsets.h"
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

DEFINE_PROFILE_CATEGORY(migrate, );

DEFINE_PROFILE_CATEGORY(checkpoint, migrate);
DEFINE_PROFILE_INTERVAL(checkpoint_create_map,  checkpoint);
DEFINE_PROFILE_INTERVAL(checkpoint_copy,        checkpoint);
DEFINE_PROFILE_CATEGORY(checkpoint_func,        checkpoint);
DEFINE_PROFILE_INTERVAL(checkpoint_destroy_map, checkpoint);

DEFINE_PROFILE_OCCURENCE(checkpoint_count,      checkpoint);
DEFINE_PROFILE_OCCURENCE(checkpoint_total_size, checkpoint);

DEFINE_PROFILE_CATEGORY(resume, migrate);
DEFINE_PROFILE_INTERVAL(child_created_in_new_process,  resume);
DEFINE_PROFILE_INTERVAL(child_wait_header,             resume);
DEFINE_PROFILE_INTERVAL(child_receive_header,          resume);
DEFINE_PROFILE_INTERVAL(do_migration,                  resume);
DEFINE_PROFILE_INTERVAL(child_load_checkpoint_on_pipe, resume);
DEFINE_PROFILE_INTERVAL(child_receive_handles,         resume);
DEFINE_PROFILE_INTERVAL(restore_checkpoint,            resume);
DEFINE_PROFILE_CATEGORY(resume_func,                   resume);
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

    LISTP_FOR_EACH_ENTRY(tmp, head, hlist)
        if (tmp->entry.addr == addr)
            e = &tmp->entry;

    if (create && !e) {
        struct cp_map_buffer * buffer = m->buffers;

        if (buffer->cnt == buffer->num)
            buffer = extend_cp_map(m);

        struct cp_map_entry *new = &buffer->entries[buffer->cnt++];
        INIT_LIST_HEAD(new, hlist);
        LISTP_ADD(new, head, hlist);

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
    __UNUSED(size);
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
    __UNUSED(offset);
    __UNUSED(rebase);

    struct shim_palhdl_entry * ent = (void *) (base + GET_CP_FUNC_ENTRY());

    if (ent->phandle && !ent->phandle && ent->uri) {
        /* XXX: reopen the stream */
    }
}
END_RS_FUNC(palhdl)

BEGIN_CP_FUNC(migratable)
{
    __UNUSED(obj);
    __UNUSED(size);
    __UNUSED(objp);
    struct shim_mem_entry * mem_entry;

    DO_CP_SIZE(memory, &__migratable, &__migratable_end - &__migratable,
               &mem_entry);

    struct shim_cp_entry * entry = ADD_CP_FUNC_ENTRY(0UL);
    mem_entry->paddr = (void **) &entry->cp_un.cp_val;
}
END_CP_FUNC(migratable)

BEGIN_RS_FUNC(migratable)
{
    __UNUSED(base);
    __UNUSED(offset);

    void * data = (void *) GET_CP_FUNC_ENTRY();
    CP_REBASE(data);
    memcpy(&__migratable, data, &__migratable_end - &__migratable);
}
END_RS_FUNC(migratable)

BEGIN_CP_FUNC(environ)
{
    __UNUSED(size);
    __UNUSED(objp);

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
    __UNUSED(offset);

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
    __UNUSED(size);
    __UNUSED(objp);

    struct shim_qstr * qstr = (struct shim_qstr *) obj;

    /* qstr is always embedded as sub-object in other objects so it is
     * automatically checkpointed as part of other checkpoint routines.
     * However, its oflow string resides in some other memory region
     * and must be checkpointed and restored explicitly. Copy oflow
     * string inside checkpoint right before qstr cp entry. */
    if (qstr->oflow) {
        struct shim_str * str =
            (void *) (base + ADD_CP_OFFSET(qstr->len + 1));
        memcpy(str, qstr->oflow, qstr->len + 1);
        ADD_CP_FUNC_ENTRY((ptr_t) qstr - base);
    }
}
END_CP_FUNC(qstr)

BEGIN_RS_FUNC(qstr)
{
    __UNUSED(offset);
    __UNUSED(rebase);

    /* If we are here, qstr has oflow string. We know that oflow string
     * is right before this qstr cp entry (aligned to 8B). Calculate
     * oflow string's base address and update qstr to point to it. */
    struct shim_qstr * qstr = (void *) (base + GET_CP_FUNC_ENTRY());
    size_t size = qstr->len + 1;
    size = ALIGN_UP(size, sizeof(void*));
    qstr->oflow = (void *)entry - size;
}
END_RS_FUNC(qstr)

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
        PAL_NUM ret = DkStreamWrite(stream, 0, total_bytes - bytes,
                                   (void *) store->base + bytes, NULL);

        if (ret == PAL_STREAM_ERROR) {
            if (PAL_ERRNO == EINTR || PAL_ERRNO == EAGAIN ||
                PAL_ERRNO == EWOULDBLOCK)
                continue;
            return -PAL_ERRNO;
        }

        bytes += ret;
    } while (bytes < total_bytes);

    ADD_PROFILE_OCCURENCE(migrate_send_on_stream, total_bytes);

    for (int i = 0 ; i < mem_nentries ; i++) {
        size_t mem_size = mem_entries[i]->size;
        void * mem_addr = mem_entries[i]->addr;

        if (!(mem_entries[i]->prot & PAL_PROT_READ) && mem_size > 0) {
            /* Make the area readable */
            if (!DkVirtualMemoryProtect(mem_addr, mem_size, mem_entries[i]->prot | PAL_PROT_READ))
                return -PAL_ERRNO;
        }

        bytes = 0;
        int error = 0;
        do {
            PAL_NUM ret = DkStreamWrite(stream, 0, mem_size - bytes,
                                       mem_addr + bytes, NULL);
            if (ret == PAL_STREAM_ERROR) {
                if (PAL_ERRNO == EINTR || PAL_ERRNO == EAGAIN ||
                    PAL_ERRNO == EWOULDBLOCK)
                    continue;
                error = -PAL_ERRNO;
                break;
            }

            bytes += ret;
        } while (bytes < mem_entries[i]->size);

        if (!(mem_entries[i]->prot & PAL_PROT_READ) && mem_size > 0) {
            /* the area was made readable above; revert to original permissions */
            if (!DkVirtualMemoryProtect(mem_addr, mem_size, mem_entries[i]->prot)) {
                if (!error) {
                    error = -PAL_ERRNO;
                }
            }
        }
        if (error < 0)
            return error;

        mem_entries[i]->size = mem_size;
        ADD_PROFILE_OCCURENCE(migrate_send_on_stream, mem_size);
    }

    return 0;
}

int restore_checkpoint (struct cp_header * cphdr, struct mem_header * memhdr,
                        ptr_t base, ptr_t type)
{
    ptr_t cpoffset = cphdr->offset;
    ptr_t * offset = &cpoffset;
    long rebase = base - (ptr_t) cphdr->addr;
    int ret = 0;

    if (type)
        debug("restore checkpoint at 0x%08lx rebased from %p (%s only)\n",
              base, cphdr->addr, CP_FUNC_NAME(type));
    else
        debug("restore checkpoint at 0x%08lx rebased from %p\n",
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

                PAL_PTR addr = ALLOC_ALIGN_DOWN_PTR(entry->addr);
                PAL_NUM size = ALLOC_ALIGN_UP_PTR(entry->addr + entry->size) - (void*)addr;
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
            SYS_PRINTF("restore_checkpoint() at %s (%d)\n",
                       CP_FUNC_NAME(cpent->cp_type), ret);
            return ret;
        }
next:
        cpent = NEXT_CP_ENTRY();
    }

    debug("successfully restore checkpoint loaded at 0x%08lx - 0x%08lx\n",
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
    __abort();
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
        if ((ret = lookup_dentry(dir, d->name, strlen(d->name),
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

        PAL_HANDLE proc = DkProcessCreate(NULL, argv);
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
    get_handle(file);
    debug("restore %s\n", filename);

    struct cp_header cphdr;
    ret = fs->fs_ops->read(file, &cphdr, sizeof(struct cp_header));
    if (ret < 0)
        goto out;

    void * cpaddr = cphdr.addr;
    ret = fs->fs_ops->mmap(file, &cpaddr, ALLOC_ALIGN_UP(cphdr.size), PROT_READ|PROT_WRITE,
                           MAP_PRIVATE|MAP_FILE, 0);
    if (ret < 0)
        goto out;

    hdr->hdr = cphdr;
    *cpptr = cpaddr;
    migrated_memory_start = cpaddr;
    migrated_memory_end = cpaddr + hdr->hdr.size;
out:
    put_handle(file);
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

    for (int i = 0 ; i < nentries ; i++) {
        /* We need to abort migration from parent to child if DkSendHandle() returned error,
         * otherwise the application may fail. */
        if (!DkSendHandle(stream, entries[i]->handle))
            return -EINVAL;
    }
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
            /* We need to abort migration from parent to child if DkReceiveHandle() returned error,
             * otherwise the application may fail. */
            if (!hdl)
                return -EINVAL;

            *entry->phandle = hdl;
        }
    }

    return 0;
}

static void * cp_alloc (struct shim_cp_store * store, void * addr, size_t size)
{
    // Keeping for api compatibility; not 100% sure this is needed
    __UNUSED(store);
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
        size_t reserve_size = ALLOC_ALIGN_UP(size >> 1);

        debug("try allocate checkpoint store (size = %ld, reserve = %ld)\n",
              size, reserve_size);

        /*
         * Allocating the checkpoint space at the first space found from the
         * top of the virtual address space.
         */
        addr = bkeep_unmapped_any(size + reserve_size, PROT_READ|PROT_WRITE,
                                  CP_VMA_FLAGS, 0, "cpstore");
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

DEFINE_PROFILE_CATEGORY(migrate_proc, migrate);
DEFINE_PROFILE_INTERVAL(migrate_create_process,   migrate_proc);
DEFINE_PROFILE_INTERVAL(migrate_connect_ipc,      migrate_proc);
DEFINE_PROFILE_INTERVAL(migrate_init_checkpoint,  migrate_proc);
DEFINE_PROFILE_INTERVAL(migrate_save_checkpoint,  migrate_proc);
DEFINE_PROFILE_INTERVAL(migrate_send_header,      migrate_proc);
DEFINE_PROFILE_INTERVAL(migrate_send_checkpoint,  migrate_proc);
DEFINE_PROFILE_OCCURENCE(migrate_send_on_stream,  migrate_proc);
DEFINE_PROFILE_INTERVAL(migrate_send_pal_handles, migrate_proc);
DEFINE_PROFILE_INTERVAL(migrate_free_checkpoint,  migrate_proc);
DEFINE_PROFILE_INTERVAL(migrate_wait_response,    migrate_proc);

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
    PAL_NUM bytes;
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
                                      pal_control.executable, argv);

    if (!proc) {
        ret = -PAL_ERRNO;
        goto out;
    }

    SAVE_PROFILE_INTERVAL(migrate_create_process);

    /* Create process and IPC bookkeepings */
    new_process = create_process(exec ? /*execve case*/ true : /*fork case*/ false);
    if (!new_process) {
        ret = -EACCES;
        goto out;
    }

    SAVE_PROFILE_INTERVAL(migrate_connect_ipc);

    /* Allocate a space for dumping the checkpoint data. */
    struct shim_cp_store cpstore;
    memset(&cpstore, 0, sizeof(cpstore));
    cpstore.alloc    = cp_alloc;
    cpstore.bound    = CP_INIT_VMA_SIZE;

    while (1) {
        /*
         * Try allocating a space of a certain size. If the allocation fails,
         * continue to try with smaller sizes.
         */
        cpstore.base = (ptr_t) cp_alloc(&cpstore, 0, cpstore.bound);
        if (cpstore.base)
            break;

        cpstore.bound >>= 1;
        if (cpstore.bound < g_pal_alloc_align)
            break;
    }

    if (!cpstore.base) {
        ret = -ENOMEM;
        debug("failed creating checkpoint store\n");
        goto out;
    }

    SAVE_PROFILE_INTERVAL(migrate_init_checkpoint);

    /* Calling the migration function defined by caller. The thread argument
     * is new thread in case of fork/clone and cur_thread in case of execve. */
    va_list ap;
    va_start(ap, thread);
    ret = (*migrate) (&cpstore, thread, new_process, ap);
    va_end(ap);
    if (ret < 0) {
        debug("failed creating checkpoint (ret = %d)\n", ret);
        goto out;
    }

    SAVE_PROFILE_INTERVAL(migrate_save_checkpoint);

    unsigned long checkpoint_time = GET_PROFILE_INTERVAL();
    unsigned long checkpoint_size = cpstore.offset + cpstore.mem_size;

    /* Checkpoint data created. */
    debug("checkpoint of %lu bytes created, %lu microsecond is spent.\n",
          checkpoint_size, checkpoint_time);

    hdr.checkpoint.hdr.addr = (void *) cpstore.base;
    hdr.checkpoint.hdr.size = checkpoint_size;

    if (cpstore.mem_nentries) {
        hdr.checkpoint.mem.entoffset =
                    (ptr_t) cpstore.last_mem_entry - cpstore.base;
        hdr.checkpoint.mem.nentries  = cpstore.mem_nentries;
    }

    if (cpstore.palhdl_nentries) {
        hdr.checkpoint.palhdl.entoffset =
                    (ptr_t) cpstore.last_palhdl_entry - cpstore.base;
        hdr.checkpoint.palhdl.nentries  = cpstore.palhdl_nentries;
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
    if (bytes == PAL_STREAM_ERROR) {
        ret = -PAL_ERRNO;
        debug("failed writing to process stream (ret = %d)\n", ret);
        goto out;
    } else if (bytes < sizeof(struct newproc_header)) {
        ret = -EACCES;
        goto out;
    }

    ADD_PROFILE_OCCURENCE(migrate_send_on_stream, bytes);
    SAVE_PROFILE_INTERVAL(migrate_send_header);

    ret = send_checkpoint_on_stream(proc, &cpstore);

    if (ret < 0) {
        debug("failed sending checkpoint (ret = %d)\n", ret);
        goto out;
    }

    SAVE_PROFILE_INTERVAL(migrate_send_checkpoint);

    /*
     * For socket and RPC streams, we need to migrate the PAL handles
     * to the new process using PAL calls.
     */
    if ((ret = send_handles_on_stream(proc, &cpstore)) < 0)
        goto out;

    SAVE_PROFILE_INTERVAL(migrate_send_pal_handles);

    /* Free the checkpoint space */
    if ((ret = bkeep_munmap((void *) cpstore.base, cpstore.bound,
                            CP_VMA_FLAGS)) < 0) {
        debug("failed unmaping checkpoint (ret = %d)\n", ret);
        goto out;
    }

    DkVirtualMemoryFree((PAL_PTR) cpstore.base, cpstore.bound);

    SAVE_PROFILE_INTERVAL(migrate_free_checkpoint);

    /* Wait for the response from the new process */
    struct newproc_response res;
    bytes = DkStreamRead(proc, 0, sizeof(struct newproc_response), &res,
                         NULL, 0);
    if (bytes == PAL_STREAM_ERROR) {
        ret = -PAL_ERRNO;
        goto out;
    }

    /* Downgrade communication with child to non-secure (only checkpoint send is secure).
     * Currently only relevant to SGX PAL, other PALs ignore this. */
    PAL_STREAM_ATTR attr;
    if (!DkStreamAttributesQueryByHandle(proc, &attr)) {
        ret = -PAL_ERRNO;
        goto out;
    }
    attr.secure = PAL_FALSE;
    if (!DkStreamAttributesSetByHandle(proc, &attr)) {
        ret = -PAL_ERRNO;
        goto out;
    }

    SAVE_PROFILE_INTERVAL(migrate_wait_response);

    /* exec != NULL implies the execve case so the new process "replaces"
     * this current process: no need to notify the leader or establish IPC */
    if (!exec) {
        /* fork/clone case: new process is an actual child process for this
         * current process, so notify the leader regarding subleasing of TID
         * (child must create self-pipe with convention of pipe:child-vmid) */
        char new_process_self_uri[256];
        snprintf(new_process_self_uri, sizeof(new_process_self_uri), URI_PREFIX_PIPE "%u", res.child_vmid);
        ipc_pid_sublease_send(res.child_vmid, thread->tid, new_process_self_uri, NULL);

        /* listen on the new IPC port to the new child process */
        add_ipc_port_by_id(res.child_vmid, proc,
                IPC_PORT_DIRCLD|IPC_PORT_LISTEN|IPC_PORT_KEEPALIVE,
                &ipc_port_with_child_fini,
                NULL);
    }

    /* remote child thread has VMID of the child process (note that we don't
     * care about execve case because the parent "intermediate" process will
     * die right after this anyway) */
    thread->vmid = res.child_vmid;

    ret = 0;
out:
    if (new_process)
        free_process(new_process);

    if (ret < 0) {
        if (proc)
            DkObjectClose(proc);
        SYS_PRINTF("process creation failed\n");
    }

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
        mapaddr = (PAL_PTR)ALLOC_ALIGN_DOWN_PTR(base);
        mapsize = (PAL_PTR)ALLOC_ALIGN_UP_PTR(base + size) - mapaddr;

        /* Need to create VMA before allocation */
        ret = bkeep_mmap((void *) mapaddr, mapsize,
                         PROT_READ|PROT_WRITE, CP_VMA_FLAGS,
                         NULL, 0, "cpstore");
        if (ret < 0)
            base = NULL;
    }
#endif

    if (!base) {
        base = bkeep_unmapped_any(ALLOC_ALIGN_UP(size), PROT_READ|PROT_WRITE, CP_VMA_FLAGS, 0,
                                  "cpstore");
        if (!base)
            return -ENOMEM;

        mapaddr = (PAL_PTR)base;
        mapsize = (PAL_NUM)ALLOC_ALIGN_UP(size);
    }

    debug("checkpoint mapped at %p-%p\n", base, base + size);

    PAL_FLG pal_prot = PAL_PROT_READ|PAL_PROT_WRITE;

    PAL_PTR mapped = DkVirtualMemoryAlloc(mapaddr, mapsize, 0, pal_prot);
    if (!mapped)
        return -PAL_ERRNO;

    assert(mapaddr == mapped);
    /*
     * If the checkpoint is loaded at a different address from where it is
     * created, we need to rebase the pointers in the checkpoint.
     */
    rebase = (long) ((uintptr_t) base - (uintptr_t) hdr->hdr.addr);

    size_t total_bytes = 0;
    while (total_bytes < size) {
        PAL_NUM bytes = DkStreamRead(PAL_CB(parent_process), 0, size - total_bytes,
                                     (void*)base + total_bytes, NULL, 0);

        if (bytes == PAL_STREAM_ERROR) {
            if (PAL_ERRNO == EINTR || PAL_ERRNO == EAGAIN ||
                    PAL_ERRNO == EWOULDBLOCK)
                continue;
            return -PAL_ERRNO;
        }

        total_bytes += bytes;
    }

    SAVE_PROFILE_INTERVAL(child_load_checkpoint_on_pipe);
    debug("%lu bytes read on stream\n", total_bytes);

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
    assert(context->regs);
    struct shim_regs regs = *context->regs;
    debug("restore context: SP = 0x%08lx, IP = 0x%08lx\n", regs.rsp, regs.rip);

    /* don't clobber redzone. If sigaltstack is used,
     * this area won't be clobbered by signal context */
    *(unsigned long*) (regs.rsp - RED_ZONE_SIZE - 8) = regs.rip;

    /* Ready to resume execution, re-enable preemption. */
    shim_tcb_t * tcb = shim_get_tcb();
    __enable_preempt(tcb);

    unsigned long fs_base = context->fs_base;
    memset(context, 0, sizeof(struct shim_context));
    context->fs_base = fs_base;

    __asm__ volatile("movq %0, %%rsp\r\n"
                     "addq $2 * 8, %%rsp\r\n"    /* skip orig_rax and rsp */
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
                     "popfq\r\n"
                     "movq "XSTRINGIFY(SHIM_REGS_RSP)" - "XSTRINGIFY(SHIM_REGS_RIP)"(%%rsp), %%rsp\r\n"
                     "movq $0, %%rax\r\n"
                     "jmp *-"XSTRINGIFY(RED_ZONE_SIZE)"-8(%%rsp)\r\n"
                     :: "g"(&regs) : "memory");
}
