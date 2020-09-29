/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains implementation of checkpoint and restore.
 */

#include "shim_checkpoint.h"

#include <asm/fcntl.h>
#include <asm/mman.h>
#include <stdarg.h>
#include <stdint.h>

#include "list.h"
#include "pal.h"
#include "pal_error.h"
#include "shim_fs.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_ipc.h"
#include "shim_lock.h"
#include "shim_process.h"
#include "shim_thread.h"
#include "shim_utils.h"
#include "shim_vma.h"

#define CP_MMAP_FLAGS    (MAP_PRIVATE | MAP_ANONYMOUS | VMA_INTERNAL)
#define CP_MAP_ENTRY_NUM 64
#define CP_HASH_SIZE     256

DEFINE_LIST(cp_map_entry);
struct cp_map_entry {
    LIST_TYPE(cp_map_entry) hlist;
    struct shim_cp_map_entry entry;
};

DEFINE_LISTP(cp_map_entry);
struct cp_map {
    struct cp_map_buffer {
        struct cp_map_buffer* next;
        size_t num;
        size_t cnt;
        struct cp_map_entry entries[0];
    }* buffers;
    LISTP_TYPE(cp_map_entry) head[CP_HASH_SIZE];
};

static struct cp_map_buffer* extend_cp_map(struct cp_map* map) {
    struct cp_map_buffer* buffer = malloc(sizeof(struct cp_map_buffer) +
                                          sizeof(struct cp_map_entry) * CP_MAP_ENTRY_NUM);
    if (!buffer)
        return NULL;

    buffer->next = map->buffers;
    buffer->num  = CP_MAP_ENTRY_NUM;
    buffer->cnt  = 0;
    map->buffers = buffer;
    return buffer;
}

void* create_cp_map(void) {
    struct cp_map* map = malloc(sizeof(*map));
    if (!map)
        return NULL;

    memset(map, 0, sizeof(*map));

    struct cp_map_buffer* buffer = extend_cp_map(map);
    if (!buffer) {
        free(map);
        return NULL;
    }

    return (void*)map;
}

void destroy_cp_map(void* _map) {
    struct cp_map* map = (struct cp_map*)_map;

    struct cp_map_buffer* buffer = map->buffers;
    while (buffer) {
        struct cp_map_buffer* next = buffer->next;
        free(buffer);
        buffer = next;
    }

    free(map);
}

struct shim_cp_map_entry* get_cp_map_entry(void* _map, void* addr, bool create) {
    struct cp_map* map = (struct cp_map*)_map;

    struct shim_cp_map_entry* e = NULL;

    /* check if object at this addr was already added to the checkpoint */
    uint64_t hash = hash64((uint64_t)addr) % CP_HASH_SIZE;
    LISTP_TYPE(cp_map_entry)* head = &map->head[hash];

    struct cp_map_entry* tmp;
    LISTP_FOR_EACH_ENTRY(tmp, head, hlist)
        if (tmp->entry.addr == addr)
            e = &tmp->entry;

    if (e)
        return e;

    /* object at this addr wasn't yet added to the checkpoint */
    if (!create)
        return NULL;

    struct cp_map_buffer* buffer = map->buffers;

    if (buffer->cnt == buffer->num) {
        buffer = extend_cp_map(map);
        if (!buffer)
            return NULL;
    }

    struct cp_map_entry* new = &buffer->entries[buffer->cnt++];
    INIT_LIST_HEAD(new, hlist);
    LISTP_ADD(new, head, hlist);

    new->entry.addr = addr;
    new->entry.off  = 0;
    return &new->entry;
}

BEGIN_CP_FUNC(memory) {
    struct shim_mem_entry* entry = (void*)(base + ADD_CP_OFFSET(sizeof(*entry)));

    entry->addr = obj;
    entry->size = size;
    entry->prot = PAL_PROT_READ | PAL_PROT_WRITE;
    entry->next = store->first_mem_entry;

    store->first_mem_entry = entry;
    store->mem_entries_cnt++;

    if (objp)
        *objp = entry;
}
END_CP_FUNC_NO_RS(memory)

BEGIN_CP_FUNC(palhdl) {
    __UNUSED(size);
    size_t off = ADD_CP_OFFSET(sizeof(struct shim_palhdl_entry));
    struct shim_palhdl_entry* entry = (void*)(base + off);

    entry->handle  = (PAL_HANDLE)obj;
    entry->uri     = NULL;
    entry->phandle = NULL;
    entry->prev    = store->last_palhdl_entry;

    store->last_palhdl_entry = entry;
    store->palhdl_entries_cnt++;

    ADD_CP_FUNC_ENTRY(off);
    if (objp)
        *objp = entry;
}
END_CP_FUNC_NO_RS(palhdl)

BEGIN_CP_FUNC(migratable) {
    __UNUSED(obj);
    __UNUSED(size);
    __UNUSED(objp);

    size_t len = &__migratable_end - &__migratable;
    size_t off = ADD_CP_OFFSET(len);
    memcpy((char*)base + off, &__migratable, len);
    ADD_CP_FUNC_ENTRY(off);
}
END_CP_FUNC(migratable)

BEGIN_RS_FUNC(migratable) {
    __UNUSED(offset);
    __UNUSED(rebase);

    const char* data = (char*)base + GET_CP_FUNC_ENTRY();
    memcpy(&__migratable, data, &__migratable_end - &__migratable);
}
END_RS_FUNC(migratable)

BEGIN_CP_FUNC(arguments) {
    __UNUSED(size);
    __UNUSED(objp);

    const char** argv = (const char**)obj;
    size_t arg_cnt    = 0;
    size_t arg_bytes  = 0;

    for (const char** a = argv; *a; a++) {
        arg_cnt++;
        arg_bytes += strlen(*a) + 1;
    }

    size_t off = ADD_CP_OFFSET(sizeof(char*) * (arg_cnt + 1) + arg_bytes);
    const char** new_argv = (void*)base + off;
    char* new_arg_str = (void*)new_argv + sizeof(char*) * (arg_cnt + 1);

    for (size_t i = 0; i < arg_cnt; i++) {
        size_t len = strlen(argv[i]);
        new_argv[i] = new_arg_str;
        memcpy(new_arg_str, argv[i], len + 1);
        new_arg_str += len + 1;
    }

    new_argv[arg_cnt] = NULL;
    ADD_CP_FUNC_ENTRY(off);
}
END_CP_FUNC(arguments)

BEGIN_RS_FUNC(arguments) {
    __UNUSED(offset);

    const char** argv = (void*)base + GET_CP_FUNC_ENTRY();
    for (const char** a = argv; *a; a++)
        CP_REBASE(*a);

    migrated_argv = argv;
}
END_RS_FUNC(arguments)

BEGIN_CP_FUNC(environ) {
    __UNUSED(size);
    __UNUSED(objp);

    const char** envp = (const char**)obj;
    size_t env_cnt    = 0;
    size_t env_bytes  = 0;

    for (const char** e = envp; *e; e++) {
        env_cnt++;
        env_bytes += strlen(*e) + 1;
    }

    size_t off = ADD_CP_OFFSET(sizeof(char*) * (env_cnt + 1) + env_bytes);
    const char** new_envp = (void*)base + off;
    char* new_env_str = (void*)new_envp + sizeof(char*) * (env_cnt + 1);

    for (size_t i = 0; i < env_cnt; i++) {
        size_t len = strlen(envp[i]);
        new_envp[i] = new_env_str;
        memcpy(new_env_str, envp[i], len + 1);
        new_env_str += len + 1;
    }

    new_envp[env_cnt] = NULL;
    ADD_CP_FUNC_ENTRY(off);
}
END_CP_FUNC(environ)

BEGIN_RS_FUNC(environ) {
    __UNUSED(offset);

    const char** envp = (void*)base + GET_CP_FUNC_ENTRY();
    for (const char** e = envp; *e; e++)
        CP_REBASE(*e);

    migrated_envp = envp;
}
END_RS_FUNC(environ)

BEGIN_CP_FUNC(qstr) {
    __UNUSED(size);
    __UNUSED(objp);

    struct shim_qstr* qstr = (struct shim_qstr*)obj;

    /* qstr is always embedded as sub-object in other objects so it is automatically checkpointed as
     * part of other checkpoint routines. However, its oflow string resides in some other memory
     * region and must be checkpointed and restored explicitly. Copy oflow string inside checkpoint
     * right before qstr cp entry. */
    if (qstr->oflow) {
        struct shim_str* str = (struct shim_str*)(base + ADD_CP_OFFSET(qstr->len + 1));
        memcpy(str, qstr->oflow, qstr->len + 1);
        ADD_CP_FUNC_ENTRY((uintptr_t)qstr - base);
    }
}
END_CP_FUNC(qstr)

BEGIN_RS_FUNC(qstr) {
    __UNUSED(offset);
    __UNUSED(rebase);

    /* If we are here, qstr has oflow string. We know that oflow string is right before this qstr cp
     * entry (aligned to 8B). Calculate oflow string's base and update qstr to point to it. */
    struct shim_qstr* qstr = (struct shim_qstr*)(base + GET_CP_FUNC_ENTRY());
    size_t size = qstr->len + 1;
    size = ALIGN_UP(size, sizeof(uintptr_t));
    qstr->oflow = (void*)entry - size;
}
END_RS_FUNC(qstr)

static int read_exact(PAL_HANDLE handle, void* buf, size_t size) {
    size_t bytes = 0;

    while (bytes < size) {
        PAL_NUM x = DkStreamRead(handle, 0, size - bytes, (char*)buf + bytes, NULL, 0);
        if (x == PAL_STREAM_ERROR) {
            int err = PAL_ERRNO();
            if (err == EINTR || err == EAGAIN || err == EWOULDBLOCK) {
                continue;
            }
            return -err;
        }

        bytes += x;
    }

    return 0;
}

static int write_exact(PAL_HANDLE handle, void* buf, size_t size) {
    size_t bytes = 0;

    while (bytes < size) {
        PAL_NUM x = DkStreamWrite(handle, 0, size - bytes, (char*)buf + bytes, NULL);
        if (x == PAL_STREAM_ERROR) {
            int err = PAL_ERRNO();
            if (err == EINTR || err == EAGAIN || err == EWOULDBLOCK) {
                continue;
            }
            return -err;
        }

        bytes += x;
    }

    return 0;
}

static int send_memory_on_stream(PAL_HANDLE stream, struct shim_cp_store* store) {
    int ret = 0;

    struct shim_mem_entry* entry = store->first_mem_entry;
    while (entry) {
        size_t mem_size = entry->size;
        void* mem_addr  = entry->addr;
        int mem_prot    = entry->prot;

        if (!(mem_prot & PAL_PROT_READ) && mem_size > 0) {
            /* make the area readable */
            if (!DkVirtualMemoryProtect(mem_addr, mem_size, mem_prot | PAL_PROT_READ)) {
                return -PAL_ERRNO();
            }
        }

        ret = write_exact(stream, mem_addr, mem_size);

        if (!(mem_prot & PAL_PROT_READ) && mem_size > 0) {
            /* the area was made readable above; revert to original permissions */
            if (!DkVirtualMemoryProtect(mem_addr, mem_size, mem_prot)) {
                if (!ret)
                    ret = -PAL_ERRNO();
            }
        }

        if (ret < 0) {
            return ret;
        }

        entry = entry->next;
    }

    return 0;
}

static int send_checkpoint_on_stream(PAL_HANDLE stream, struct shim_cp_store* store) {
    /* first send non-memory entries found at [store->base, store->base + store->offset) */
    int ret = write_exact(stream, (void*)store->base, store->offset);
    if (ret < 0) {
        return ret;
    }

    return send_memory_on_stream(stream, store);
}

static int send_handles_on_stream(PAL_HANDLE stream, struct shim_cp_store* store) {
    int ret;

    size_t entries_cnt = store->palhdl_entries_cnt;
    if (!entries_cnt)
        return 0;

    struct shim_palhdl_entry** entries = malloc(sizeof(*entries) * entries_cnt);
    if (!entries)
        return -ENOMEM;

    /* PAL-handle entries were added in reverse order, let's first populate them */
    struct shim_palhdl_entry* entry = store->last_palhdl_entry;
    for (size_t i = entries_cnt; i > 0; i--) {
        assert(entry);
        entries[i - 1] = entry;
        entry = entry->prev;
    }
    assert(!entry);

    /* now we can traverse PAL-handle entries in correct order and send them one by one */
    for (size_t i = 0; i < entries_cnt; i++) {
        /* we need to abort migration if DkSendHandle() returned error, otherwise app may fail */
        if (!DkSendHandle(stream, entries[i]->handle)) {
            ret = -EINVAL;
            goto out;
        }
    }

    ret = 0;
out:
    free(entries);
    return ret;
}

static int receive_memory_on_stream(PAL_HANDLE handle, struct checkpoint_hdr* hdr, uintptr_t base) {
    ssize_t rebase = base - (uintptr_t)hdr->addr;

    if (hdr->mem_entries_cnt) {
        struct shim_mem_entry* entry = (struct shim_mem_entry*)(base + hdr->mem_offset);

        for (; entry; entry = entry->next) {
            CP_REBASE(entry->next);

            debug("memory entry [%p]: %p-%p\n", entry, entry->addr, entry->addr + entry->size);

            PAL_PTR addr = ALLOC_ALIGN_DOWN_PTR(entry->addr);
            PAL_NUM size = (char*)ALLOC_ALIGN_UP_PTR(entry->addr + entry->size) - (char*)addr;
            PAL_FLG prot = entry->prot;

            if (!DkVirtualMemoryAlloc(addr, size, 0, prot | PAL_PROT_WRITE)) {
                debug("failed allocating %p-%p\n", addr, addr + size);
                return -PAL_ERRNO();
            }

            int ret = read_exact(handle, entry->addr, entry->size);
            if (ret < 0) {
                return ret;
            }

            if (!(prot & PAL_PROT_WRITE) && !DkVirtualMemoryProtect(addr, size, prot)) {
                debug("failed protecting %p-%p\n", addr, addr + size);
                return -PAL_ERRNO();
            }
        }
    }

    return 0;
}

static int restore_checkpoint(struct checkpoint_hdr* hdr, uintptr_t base) {
    size_t cpoffset = hdr->offset;
    size_t* offset  = &cpoffset;

    debug("restoring checkpoint at 0x%08lx rebased from %p\n", base, hdr->addr);

    struct shim_cp_entry* cpent = NEXT_CP_ENTRY();
    ssize_t rebase = base - (uintptr_t)hdr->addr;

    while (cpent) {
        if (cpent->cp_type < CP_FUNC_BASE) {
            cpent = NEXT_CP_ENTRY();
            continue;
        }

        rs_func rs = (&__rs_func)[cpent->cp_type - CP_FUNC_BASE];
        int ret = (*rs)(cpent, base, offset, rebase);
        if (ret < 0) {
            debug("failed restoring checkpoint at %s (%d)\n", CP_FUNC_NAME(cpent->cp_type), ret);
            return ret;
        }
        cpent = NEXT_CP_ENTRY();
    }

    debug("successfully restored checkpoint at 0x%08lx - 0x%08lx\n", base, base + hdr->size);
    return 0;
}

static int receive_handles_on_stream(struct checkpoint_hdr* hdr, void* base, ssize_t rebase) {
    int ret;

    struct shim_palhdl_entry* palhdl_entries = (struct shim_palhdl_entry*)(base +
                                                                           hdr->palhdl_offset);

    size_t entries_cnt = hdr->palhdl_entries_cnt;
    if (!entries_cnt)
        return 0;

    debug("receiving %lu PAL handles\n", entries_cnt);

    struct shim_palhdl_entry** entries = malloc(sizeof(*entries) * entries_cnt);

    /* entries are extracted from checkpoint in reverse order, let's first populate them */
    struct shim_palhdl_entry* entry = palhdl_entries;
    for (size_t i = entries_cnt; i > 0; i--) {
        assert(entry);
        CP_REBASE(entry->prev);
        CP_REBASE(entry->phandle);
        entries[i - 1] = entry;
        entry = entry->prev;
    }
    assert(!entry);

    /* now we can traverse PAL-handle entries in correct order and receive them one by one */
    for (size_t i = 0; i < entries_cnt; i++) {
        entry = entries[i];
        if (!entry->handle)
            continue;

        PAL_HANDLE hdl = DkReceiveHandle(PAL_CB(parent_process));
        /* need to abort migration if DkReceiveHandle() returned error, otherwise app may fail */
        if (!hdl) {
            ret = -EINVAL;
            goto out;
        }
        *entry->phandle = hdl;
    }

    ret = 0;
out:
    free(entries);
    return ret;
}

static void* cp_alloc(void* addr, size_t size) {
    if (addr) {
        debug("extending checkpoint store: %p-%p (size = %lu)\n", addr, addr + size, size);

        if (bkeep_mmap_fixed(addr, size, PROT_READ | PROT_WRITE,
                             CP_MMAP_FLAGS | MAP_FIXED_NOREPLACE, NULL, 0, "cpstore") < 0)
            return NULL;
    } else {
        /* FIXME: It is unclear if the below strategy helps */
        /* Here we use a strategy to reduce internal fragmentation of virtual memory space. Because
         * we need a relatively large, continuous space for dumping the checkpoint data, internal
         * fragmentation can cause the process to drain the virtual address space after forking a
         * few times. The previous space used for checkpoint may be fragmented at the next fork.
         * A simple trick we use here is to reserve some space right after the checkpoint space. The
         * reserved space is half of the size of the checkpoint space. */
        size_t reserve_size = ALLOC_ALIGN_UP(size >> 1);

        debug("allocating checkpoint store (size = %ld, reserve = %ld)\n", size, reserve_size);

        int ret = bkeep_mmap_any(size + reserve_size, PROT_READ | PROT_WRITE, CP_MMAP_FLAGS, NULL,
                                 0, "cpstore", &addr);
        if (ret < 0) {
            return NULL;
        }

        /* we reserved [addr, addr + size + reserve_size) to reduce fragmentation (see above); now
         * we unmap [addr + size, addr + size + reserve_size) to reclaim this memory region */
        void* tmp_vma = NULL;
        if (bkeep_munmap(addr + size, reserve_size, /*is_internal=*/true, &tmp_vma) < 0) {
            BUG();
        }
        bkeep_remove_tmp_vma(tmp_vma);
    }

    addr = (void*)DkVirtualMemoryAlloc(addr, size, 0, PAL_PROT_READ | PAL_PROT_WRITE);
    if (!addr) {
        void* tmp_vma = NULL;
        if (bkeep_munmap(addr, size, /*is_internal=*/true, &tmp_vma) < 0) {
            BUG();
        }
        bkeep_remove_tmp_vma(tmp_vma);
    }

    return addr;
}

int create_process_and_send_checkpoint(migrate_func_t migrate_func, struct shim_handle* exec,
                                       struct shim_child_process* child_process,
                                       struct shim_process* process_description,
                                       struct shim_thread* thread_description, ...) {
    assert(exec || child_process);

    int ret = 0;
    struct shim_process_ipc_info* process_ipc_info = NULL;

    /* FIXME: Child process requires some time to initialize before starting to receive checkpoint
     * data. Parallelizing process creation and checkpointing could improve latency of forking. */
    const char* exec_uri = exec ? /*execve*/ qstrgetstr(&exec->uri)
                                : /*fork*/ pal_control.executable;
    PAL_HANDLE pal_process = DkProcessCreate(exec_uri, /*args=*/NULL);
    if (!pal_process) {
        ret = -PAL_ERRNO();
        goto out;
    }

    /* Create IPC bookkeepings for the new process. */
    process_ipc_info = create_process_ipc_info(exec ? /*execve*/ true : /*fork*/ false);
    if (!process_ipc_info) {
        ret = -EACCES;
        goto out;
    }

    /* in exec case, need to migrate PAL handles for self/parent IPC; simply set them in new
     * process_ipc_info object so migration function notices and migrates them, and revert back
     * after migration at the end of this function (we do this pointer assignment because there is
     * no notion of refcounts for PAL handles at LibOS level) */
    if (exec) {
        lock(&g_process_ipc_info.lock);
        process_ipc_info->self->pal_handle = g_process_ipc_info.self->pal_handle;
        if (process_ipc_info->parent)
            process_ipc_info->parent->pal_handle = g_process_ipc_info.parent->pal_handle;
        unlock(&g_process_ipc_info.lock);
    }

    /* allocate a space for dumping the checkpoint data */
    struct shim_cp_store cpstore;
    memset(&cpstore, 0, sizeof(cpstore));
    cpstore.alloc = cp_alloc;
    cpstore.bound = CP_INIT_VMA_SIZE;

    while (1) {
        /* try allocating checkpoint; if allocation fails, try with smaller sizes */
        cpstore.base = (uintptr_t)cp_alloc(0, cpstore.bound);
        if (cpstore.base)
            break;

        cpstore.bound >>= 1;
        if (cpstore.bound < g_pal_alloc_align)
            break;
    }

    if (!cpstore.base) {
        ret = -ENOMEM;
        debug("failed allocating enough memory for checkpoint\n");
        goto out;
    }

    va_list ap;
    va_start(ap, thread_description);
    ret = (*migrate_func)(&cpstore, process_description, thread_description, process_ipc_info, ap);
    va_end(ap);
    if (ret < 0) {
        debug("failed creating checkpoint (ret = %d)\n", ret);
        goto out;
    }

    debug("checkpoint of %lu bytes created\n", cpstore.offset);

    struct checkpoint_hdr hdr;
    memset(&hdr, 0, sizeof(hdr));

    hdr.addr = (void*)cpstore.base;
    hdr.size = cpstore.offset;

    if (cpstore.mem_entries_cnt) {
        hdr.mem_offset      = (uintptr_t)cpstore.first_mem_entry - cpstore.base;
        hdr.mem_entries_cnt = cpstore.mem_entries_cnt;
    }

    if (cpstore.palhdl_entries_cnt) {
        hdr.palhdl_offset      = (uintptr_t)cpstore.last_palhdl_entry - cpstore.base;
        hdr.palhdl_entries_cnt = cpstore.palhdl_entries_cnt;
    }

    /* send a checkpoint header to child process to notify it to start receiving checkpoint */
    ret = write_exact(pal_process, &hdr, sizeof(hdr));
    if (ret < 0) {
        debug("failed writing checkpoint header to child process (ret = %d)\n", ret);
        goto out;
    }

    ret = send_checkpoint_on_stream(pal_process, &cpstore);
    if (ret < 0) {
        debug("failed sending checkpoint (ret = %d)\n", ret);
        goto out;
    }

    ret = send_handles_on_stream(pal_process, &cpstore);
    if (ret < 0) {
        debug("failed sending PAL handles as part of checkpoint (ret = %d)\n", ret);
        goto out;
    }

    void* tmp_vma = NULL;
    ret = bkeep_munmap((void*)cpstore.base, cpstore.bound, /*is_internal=*/true, &tmp_vma);
    if (ret < 0) {
        debug("failed unmaping checkpoint (ret = %d)\n", ret);
        goto out;
    }
    DkVirtualMemoryFree((PAL_PTR)cpstore.base, cpstore.bound);
    bkeep_remove_tmp_vma(tmp_vma);

    /* wait for final ack from child process (contains VMID of child) */
    IDTYPE child_vmid = 0;
    ret = read_exact(pal_process, &child_vmid, sizeof(child_vmid));
    if (ret < 0) {
        goto out;
    }

    if (exec) {
        /* execve case: child process "replaces" this current process: no need to notify the leader
         * or establish IPC, the only thing to do is revert self/parent PAL handles' pointers */
        process_ipc_info->self->pal_handle = NULL;
        if (process_ipc_info->parent)
            process_ipc_info->parent->pal_handle = NULL;
    } else {
        /* Child creation was successful, now we add it to the children list. This needs to be done
         * before we start handling async IPC messages from this child (done below). */
        child_process->vmid = child_vmid;
        add_child_process(child_process);

        /* fork/clone case: new process is an actual child process for this current process, so
         * notify the leader regarding subleasing of TID (child must create self-pipe with
         * convention of pipe:child-vmid) */
        char process_self_uri[256];
        snprintf(process_self_uri, sizeof(process_self_uri), URI_PREFIX_PIPE "%u", child_vmid);
        ipc_sublease_send(child_vmid, thread_description->tid, process_self_uri);

        /* create new IPC port to communicate over pal_process channel with the child process */
        add_ipc_port_by_id(child_vmid, pal_process, IPC_PORT_CONNECTION | IPC_PORT_DIRECTCHILD,
                           &ipc_port_with_child_fini, NULL);
    }

    ret = 0;
out:
    if (process_ipc_info)
        free_process_ipc_info(process_ipc_info);

    if (ret < 0) {
        if (pal_process)
            DkObjectClose(pal_process);
        debug("process creation failed\n");
    }

    return ret;
}

int receive_checkpoint_and_restore(struct checkpoint_hdr* hdr) {
    int ret = 0;
    PAL_PTR mapped = NULL;

    void* base = hdr->addr;
    PAL_PTR mapaddr = (PAL_PTR)ALLOC_ALIGN_DOWN_PTR(base);
    PAL_NUM mapsize = (PAL_PTR)ALLOC_ALIGN_UP_PTR(base + hdr->size) - mapaddr;

    /* first try allocating at address used by parent process */
    if (PAL_CB(user_address.start) <= mapaddr && mapaddr + mapsize <= PAL_CB(user_address.end)) {
        ret = bkeep_mmap_fixed((void*)mapaddr, mapsize, PROT_READ | PROT_WRITE,
                               CP_MMAP_FLAGS | MAP_FIXED_NOREPLACE, NULL, 0, "cpstore");
        if (ret < 0) {
            /* the address used by parent overlaps with this child's memory regions */
            base = NULL;
        }
    } else {
        /* this region is not available to LibOS in the current Graphene instance */
        base = NULL;
    }

    if (!base) {
        /* address used by parent process is occupied; allocate checkpoint anywhere */
        ret = bkeep_mmap_any(ALLOC_ALIGN_UP(hdr->size), PROT_READ | PROT_WRITE, CP_MMAP_FLAGS, NULL,
                             0, "cpstore", &base);
        if (ret < 0) {
            return ret;
        }

        mapaddr = (PAL_PTR)base;
        mapsize = (PAL_NUM)ALLOC_ALIGN_UP(hdr->size);
    }

    debug("checkpoint mapped at %p-%p\n", base, base + hdr->size);

    mapped = DkVirtualMemoryAlloc(mapaddr, mapsize, 0, PAL_PROT_READ | PAL_PROT_WRITE);
    if (!mapped) {
        ret = -PAL_ERRNO();
        goto out;
    }
    assert(mapaddr == mapped);

    ret = read_exact(PAL_CB(parent_process), base, hdr->size);
    if (ret < 0) {
        goto out;
    }
    debug("read checkpoint of %lu bytes from parent\n", hdr->size);

    ret = receive_memory_on_stream(PAL_CB(parent_process), hdr, (uintptr_t)base);
    if (ret < 0) {
        goto out;
    }
    debug("restored memory from checkpoint\n");

    /* if checkpoint is loaded at a different address in child from where it was created in parent,
     * need to rebase the pointers in the checkpoint */
    ssize_t rebase = (ssize_t)(base - hdr->addr);

    ret = receive_handles_on_stream(hdr, base, rebase);
    if (ret < 0) {
        goto out;
    }

    migrated_memory_start = (void*)mapaddr;
    migrated_memory_end   = (void*)mapaddr + mapsize;

    ret = restore_checkpoint(hdr, (uintptr_t)base);
    if (ret < 0) {
        goto out;
    }

    ret = 0;
out:
    if (ret < 0) {
        void* tmp_vma = NULL;
        if (mapaddr)
            if (bkeep_munmap(mapaddr, mapsize, /*is_internal=*/true, &tmp_vma) < 0)
                BUG();
        if (mapped)
            DkVirtualMemoryFree(mapped, mapsize);
        if (mapaddr)
            bkeep_remove_tmp_vma(tmp_vma);
    }
    return ret;
}
