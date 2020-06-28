/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * shim_checkpoint.h
 *
 * This file contains definitions and macros for checkpointing.
 */

#ifndef _SHIM_CHECKPOINT_H_
#define _SHIM_CHECKPOINT_H_

#include <stdarg.h>
#include <stdint.h>

#include "pal.h"

#include "shim_defs.h"
#include "shim_ipc.h"

#define __attribute_migratable __attribute__((section(".migratable")))

extern char __migratable;
extern char __migratable_end;

/* FIXME: Checkpointing must be de-macroed and simplified */

/* TSAI 7/11/2012:
   The checkpoint scheme we are expecting is to support an easy syntax to
   implement migration procedure. A migration procedure can be written
   in the following syntax:

   BEGIN_CP_DEFINITION(exec) {
       DEFINE_CP(thread, ...);
       DEFINE_CP(handle_map, ...);
   }
   void* checkpoint = DO_CHECKPOINT(exec);

   Below is the figure for our checkpoint structure:

   Low Bytes -------------------------------------------------
                checkpoint_entry[0]
                data section for checkpoint 0
                checkpoint_entry[1]
                data section for checkpoint 1
                checkpoint_entry[2]
                ...
                checkpoint_entry[n]  CP_NULL
   High Bytes ------------------------------------------------
*/

struct shim_cp_entry {
    uintptr_t cp_type;
    uintptr_t cp_val;
};

struct shim_mem_entry {
    struct shim_mem_entry* prev;
    void* addr;
    size_t size;
    void** paddr;
    void* data;
    int prot;     /* combination of PAL_PROT_* flags */
};

struct shim_palhdl_entry {
    struct shim_palhdl_entry* prev;
    PAL_HANDLE handle;
    struct shim_qstr* uri;
    PAL_HANDLE* phandle;
};

struct shim_cp_store {
    /* checkpoint data mapping */
    void* cp_map;
    struct shim_handle* cp_file;

    /* allocation method for checkpoint area */
    void* (*alloc)(void*, size_t);

    /* checkpoint area */
    uintptr_t base;
    size_t offset;
    size_t bound;

    /* VMA entries */
    struct shim_mem_entry* last_mem_entry;
    size_t mem_entries_cnt;
    size_t mem_size;

    /* PAL-handle entries */
    struct shim_palhdl_entry* last_palhdl_entry;
    size_t palhdl_entries_cnt;
};

#define CP_FUNC_ARGS struct shim_cp_store* store, void* obj, size_t size, void** objp

#define RS_FUNC_ARGS struct shim_cp_entry* entry, uintptr_t base, size_t* offset, size_t rebase

#define DEFINE_CP_FUNC(name) int cp_##name(CP_FUNC_ARGS)
#define DEFINE_RS_FUNC(name) int rs_##name(RS_FUNC_ARGS)

typedef int (*cp_func)(CP_FUNC_ARGS);
typedef int (*rs_func)(RS_FUNC_ARGS);

extern const char* __cp_name;
extern const cp_func __cp_func;
extern const rs_func __rs_func;

enum {
    CP_NULL = 0,
    CP_OOB,
    CP_ADDR,
    CP_SIZE,
    CP_FUNC_BASE,
};

#define CP_FUNC_INDEX(name)                  \
    ({                                       \
        extern const cp_func cp_func_##name; \
        &cp_func_##name - &__cp_func;        \
    })

#define CP_FUNC(name)      (CP_FUNC_BASE + CP_FUNC_INDEX(name))
#define CP_FUNC_NAME(type) ((&__cp_name)[(type) - CP_FUNC_BASE])

#define __ADD_CP_OFFSET(size)                                                                     \
    ({                                                                                            \
        size_t _off = store->offset;                                                              \
        if (store->offset + (size) > store->bound) {                                              \
            size_t new_bound = store->bound * 2;                                                  \
                                                                                                  \
            while (store->offset + (size) > new_bound)                                            \
                new_bound *= 2;                                                                   \
                                                                                                  \
            void* buf =                                                                           \
                store->alloc((void*)store->base + store->bound, new_bound - store->bound);        \
            if (!buf)                                                                             \
                return -ENOMEM;                                                                   \
                                                                                                  \
            store->bound = new_bound;                                                             \
        }                                                                                         \
        store->offset += (size);                                                                  \
        _off;                                                                                     \
    })

#define ADD_CP_ENTRY(type, value)                                                                \
    ({                                                                                           \
        struct shim_cp_entry* tmp = (void*)base + __ADD_CP_OFFSET(sizeof(struct shim_cp_entry)); \
        tmp->cp_type              = CP_##type;                                                   \
        tmp->cp_val               = (uintptr_t)(value);                                          \
        tmp;                                                                                     \
    })

#define ADD_CP_OFFSET(size)                                                                      \
    ({                                                                                           \
        size_t _size              = ALIGN_UP(size, sizeof(void*));                               \
        struct shim_cp_entry* oob = (void*)base + __ADD_CP_OFFSET(sizeof(struct shim_cp_entry)); \
        oob->cp_type              = CP_OOB;                                                      \
        oob->cp_val               = (uintptr_t)_size;                                            \
        size_t _off               = __ADD_CP_OFFSET(_size);                                      \
        _off;                                                                                    \
    })

#define ADD_CP_FUNC_ENTRY(value)                                                                 \
    ({                                                                                           \
        struct shim_cp_entry* tmp = (void*)base + __ADD_CP_OFFSET(sizeof(struct shim_cp_entry)); \
        tmp->cp_type              = CP_FUNC_TYPE;                                                \
        tmp->cp_val               = (uintptr_t)(value);                                          \
        tmp;                                                                                     \
    })

#define NEXT_CP_ENTRY()                              \
    ({                                               \
        struct shim_cp_entry* tmp;                   \
        while (1) {                                  \
            tmp = (void*)base + *offset;             \
            if (tmp->cp_type == CP_NULL) {           \
                tmp = NULL;                          \
                break;                               \
            }                                        \
            *offset += sizeof(struct shim_cp_entry); \
            if (tmp->cp_type == CP_OOB)              \
                *offset += tmp->cp_val;              \
            else                                     \
                break;                               \
        }                                            \
        tmp;                                         \
    })

#define GET_CP_ENTRY(type)                           \
    ({                                               \
        struct shim_cp_entry* tmp = NEXT_CP_ENTRY(); \
        while (tmp->cp_type != CP_##type)            \
            tmp = NEXT_CP_ENTRY();                   \
        tmp->cp_val;                                 \
    })

#define GET_CP_FUNC_ENTRY()  \
    ({                       \
        entry->cp_val;       \
    })

#define BEGIN_CP_FUNC(name)                                                                \
    const char* cp_name_##name __attribute__((section(".cp_name." #name))) = #name;        \
    extern DEFINE_CP_FUNC(name);                                                           \
    extern DEFINE_RS_FUNC(name);                                                           \
    const cp_func cp_func_##name __attribute__((section(".cp_func." #name))) = &cp_##name; \
    const rs_func rs_func_##name __attribute__((section(".rs_func." #name))) = &rs_##name; \
                                                                                           \
    DEFINE_CP_FUNC(name) {                                                                 \
        int CP_FUNC_TYPE __attribute__((unused))         = CP_FUNC(name);                  \
        const char* CP_FUNC_NAME __attribute__((unused)) = #name;                          \
        size_t base __attribute__((unused))              = store->base;

#define END_CP_FUNC(name)  \
        return 0;          \
    }

#define END_CP_FUNC_NO_RS(name) \
    END_CP_FUNC(name)           \
    BEGIN_RS_FUNC(name) {       \
        __UNUSED(entry);        \
        __UNUSED(base);         \
        __UNUSED(offset);       \
        __UNUSED(rebase);       \
    }                           \
    END_RS_FUNC(name)

#define BEGIN_RS_FUNC(name)                                               \
    DEFINE_RS_FUNC(name) {                                                \
        int CP_FUNC_TYPE __attribute__((unused))         = CP_FUNC(name); \
        const char* CP_FUNC_NAME __attribute__((unused)) = #name;

#define END_RS_FUNC(name)  \
        return 0;          \
    }

#define CP_REBASE(obj)                                     \
    do {                                                   \
        void* _ptr   = &(obj);                             \
        size_t _size = sizeof(obj);                        \
        void** _p;                                         \
        for (_p = _ptr; _p < (void**)(_ptr + _size); _p++) \
            if (*_p)                                       \
                *_p += rebase;                             \
    } while (0)

#define DO_CP_SIZE(name, obj, size, objp)                      \
    do {                                                       \
        extern DEFINE_CP_FUNC(name);                           \
        int ret = cp_##name(store, obj, size, (void**)(objp)); \
        if (ret < 0)                                           \
            return ret;                                        \
    } while (0)

#define DO_CP(name, obj, objp)                  DO_CP_SIZE(name, obj, sizeof(*(obj)), objp)
#define DO_CP_MEMBER(name, obj, newobj, member) DO_CP(name, (obj)->member, &((newobj)->member));
#define DO_CP_IN_MEMBER(name, obj, member)      DO_CP(name, &((obj)->member), NULL)

struct shim_cp_map_entry {
    void* addr;
    size_t off;
};

void* create_cp_map(void);
void destroy_cp_map(void* map);
struct shim_cp_map_entry* get_cp_map_entry(void* map, void* addr, bool create);

#define GET_FROM_CP_MAP(obj)                                                       \
    ({                                                                             \
        struct shim_cp_map_entry* e = get_cp_map_entry(store->cp_map, obj, false); \
        e ? e->off : 0;                                                            \
    })

#define ADD_TO_CP_MAP(obj, off)                                                   \
    do {                                                                          \
        struct shim_cp_map_entry* e = get_cp_map_entry(store->cp_map, obj, true); \
        e->off                      = (off);                                      \
    } while (0)

#define BEGIN_MIGRATION_DEF(name, ...)                                  \
    int migrate_cp_##name(struct shim_cp_store* store, ##__VA_ARGS__) { \
        int ret     = 0;                                                \
        size_t base = store->base;

#define END_MIGRATION_DEF(name)     \
        ADD_CP_ENTRY(NULL, 0);      \
        return 0;                   \
    }

#define DEFINE_MIGRATE(name, obj, size)                    \
    do {                                                   \
        extern DEFINE_CP_FUNC(name);                       \
        if ((ret = cp_##name(store, obj, size, NULL)) < 0) \
            return ret;                                    \
    } while (0)

#define DEBUG_RESUME 0

#if DEBUG_RESUME == 1
#define DEBUG_RS(fmt, ...) \
    debug("GET %s(0x%08lx): " fmt "\n", CP_FUNC_NAME, entry->cp_val, ##__VA_ARGS__)
#else
#define DEBUG_RS(...) do {} while (0)
#endif

#define START_MIGRATE(store, name, ...)                                    \
    ({                                                                     \
        int ret = 0;                                                       \
        do {                                                               \
            if (!((store)->cp_map = create_cp_map())) {                    \
                ret = -ENOMEM;                                             \
                goto out;                                                  \
            }                                                              \
            ret = migrate_cp_##name(store, ##__VA_ARGS__);                 \
            if (ret < 0)                                                   \
                goto out;                                                  \
                                                                           \
            debug("complete checkpointing data\n");                        \
        out:                                                               \
            destroy_cp_map((store)->cp_map);                               \
        } while (0);                                                       \
        ret;                                                               \
    })

struct checkpoint_hdr {
    void* addr;
    size_t size;
    size_t offset;

    size_t mem_offset;
    size_t mem_entries_cnt;

    size_t palhdl_offset;
    size_t palhdl_entries_cnt;
};

typedef int (*migrate_func_t)(struct shim_cp_store*, struct shim_thread*, struct shim_process*,
                              va_list);

/*!
 * \brief Create child process and migrate current-process state to it.
 *
 * Called in parent process during fork/clone/execve.
 *
 * \param migrate_func Migration function defined by the caller.
 * \param exec         Executable to load in the child process.
 * \param thread       Main-thread handle to be migrated to the child process.
 *
 * The remaining arguments are passed into the migration function.
 *
 * \return             0 on success, negative POSIX error code on failure.
 */
int create_process_and_send_checkpoint(migrate_func_t migrate_func, struct shim_handle* exec,
                                       struct shim_thread* thread, ...);

/*!
 * \brief Receive a checkpoint from parent process and restore state based on it.
 *
 * Called in child process during initialization.
 *
 * \param[in] hdr  Checkpoint header already received from the parent.
 *
 * \return         0 on success, negative POSIX error code on failure.
 */
int receive_checkpoint_and_restore(struct checkpoint_hdr* hdr);

#endif /* _SHIM_CHECKPOINT_H_ */
