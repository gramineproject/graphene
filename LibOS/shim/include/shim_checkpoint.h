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
 * shim_checkpoints.c
 *
 * This file contains definitions and macros for checkpointing method.
 */

#ifndef _SHIM_CHECKPOINT_H_
#define _SHIM_CHECKPOINT_H_

#include <stdarg.h>

#include <pal.h>
#include <shim_defs.h>
#include <shim_ipc.h>
#include <shim_profile.h>

#ifdef __i386__
#error "x86-32 support is heavily broken."
#endif

typedef uint64_t ptr_t;
#define hashfunc hash64

#define __attribute_migratable __attribute__((section(".migratable")))

extern char __migratable;
extern char __migratable_end;

/* TSAI 7/11/2012:
   The checkpoint scheme we are expecting is to support an easy syntax to
   implement migration procedure. A migration procedure can be written
   in the following syntax:

   BEGIN_CP_DEFINITION(exec)
   {
       DEFINE_CP(thread, ...);
       DEFINE_CP(handle_map, ...);
   }
   void * checkpoint = DO_CHECKPOINT(exec);

   The structure of checkpoint data will be a counting-down stack-like
   memory segment, with enough space reserved below for 1. in case the
   dry run miscalculate the checkpoint size or 2. stack use for the new
   thread.

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
    ptr_t cp_type;  /* entry type */
    union {
        ptr_t cp_val;  /* integer value */
        /* originally there is a pointer, now we don't need them */
    } cp_un;
};

struct shim_mem_entry {
    struct shim_mem_entry* prev;
    void* addr;
    size_t size;
    void** paddr;
    int prot;
    void* data;
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

    /* allocation method for check point area */
    void* (*alloc)(struct shim_cp_store*, void*, size_t);

    /* check point area */
    ptr_t base, offset, bound;

    /* entries of out-of-band data */
    struct shim_mem_entry* last_mem_entry;
    int mem_nentries;
    size_t mem_size;

    /* entries of pal handles to send */
    struct shim_palhdl_entry* last_palhdl_entry;
    int palhdl_nentries;
};

#define CP_FUNC_ARGS struct shim_cp_store* store, void* obj, size_t size, void** objp

#define RS_FUNC_ARGS struct shim_cp_entry* entry, ptr_t base, ptr_t* offset, long rebase

#define DEFINE_CP_FUNC(name) int cp_##name(CP_FUNC_ARGS)
#define DEFINE_RS_FUNC(name) int rs_##name(RS_FUNC_ARGS)

typedef int (*cp_func)(CP_FUNC_ARGS);
typedef int (*rs_func)(RS_FUNC_ARGS);

extern const char* __cp_name;
extern const cp_func __cp_func;
extern const rs_func __rs_func;

enum {
    CP_NULL = 0,
    CP_IGNORE,
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
        ptr_t _off = store->offset;                                                               \
        if (store->offset + (size) > store->bound) {                                              \
            ptr_t new_bound = store->bound * 2;                                                   \
                                                                                                  \
            while (store->offset + (size) > new_bound)                                            \
                new_bound *= 2;                                                                   \
                                                                                                  \
            void* buf =                                                                           \
                store->alloc(store, (void*)store->base + store->bound, new_bound - store->bound); \
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
        tmp->cp_un.cp_val         = (ptr_t)(value);                                              \
        if (DEBUG_CHECKPOINT)                                                                    \
            debug("ADD CP_" #type "(0x%08lx) >%ld\n", tmp->cp_un.cp_val, store->offset);         \
        tmp;                                                                                     \
    })

#define ADD_CP_OFFSET(size)                                                                      \
    ({                                                                                           \
        size_t _size              = ALIGN_UP(size, sizeof(void*));                               \
        struct shim_cp_entry* oob = (void*)base + __ADD_CP_OFFSET(sizeof(struct shim_cp_entry)); \
        oob->cp_type              = CP_OOB;                                                      \
        oob->cp_un.cp_val         = (ptr_t)_size;                                                \
        ptr_t _off                = (ptr_t)__ADD_CP_OFFSET(_size);                               \
        if (DEBUG_CHECKPOINT)                                                                    \
            debug("ADD OFFSET(%lu) >%ld\n", size, store->offset);                                \
        _off;                                                                                    \
    })

#define ADD_CP_FUNC_ENTRY(value)                                                                 \
    ({                                                                                           \
        struct shim_cp_entry* tmp = (void*)base + __ADD_CP_OFFSET(sizeof(struct shim_cp_entry)); \
        tmp->cp_type              = CP_FUNC_TYPE;                                                \
        tmp->cp_un.cp_val         = (ptr_t)(value);                                              \
        if (DEBUG_CHECKPOINT)                                                                    \
            debug("ADD %s(0x%08lx) >%ld\n", CP_FUNC_NAME, value, store->offset);                 \
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
                *offset += tmp->cp_un.cp_val;        \
            else                                     \
                break;                               \
        }                                            \
        tmp;                                         \
    })

#define GET_CP_ENTRY(type)                                       \
    ({                                                           \
        struct shim_cp_entry* tmp = NEXT_CP_ENTRY();             \
                                                                 \
        while (tmp->cp_type != CP_##type)                        \
            tmp = NEXT_CP_ENTRY();                               \
                                                                 \
        /* debug("GET CP_" #type "(%p)\n",tmp->cp_un.cp_val); */ \
        tmp->cp_un.cp_val;                                       \
    })

#define GET_CP_FUNC_ENTRY()                                                         \
    ({                                                                              \
        /* debug("GET CP_FUNC_%s(%p) :%d\n", CP_FUNC_NAME, entry->cp_un.cp_val); */ \
        entry->cp_un.cp_val;                                                        \
    })

#define BEGIN_CP_FUNC(name)                                                                \
    const char* cp_name_##name __attribute__((section(".cp_name." #name))) = #name;        \
    extern DEFINE_CP_FUNC(name);                                                           \
    extern DEFINE_RS_FUNC(name);                                                           \
    const cp_func cp_func_##name __attribute__((section(".cp_func." #name))) = &cp_##name; \
    const rs_func rs_func_##name __attribute__((section(".rs_func." #name))) = &rs_##name; \
                                                                                           \
    DEFINE_PROFILE_INTERVAL(cp_##name, checkpoint_func);                                   \
    DEFINE_PROFILE_INTERVAL(rs_##name, resume_func);                                       \
                                                                                           \
    DEFINE_CP_FUNC(name) {                                                                 \
        int CP_FUNC_TYPE __attribute__((unused))         = CP_FUNC(name);                  \
        const char* CP_FUNC_NAME __attribute__((unused)) = #name;                          \
        ptr_t base __attribute__((unused))               = store->base;                    \
        BEGIN_PROFILE_INTERVAL();                                                          \
        ASSIGN_PROFILE_INTERVAL(cp_##name);

#define END_CP_FUNC(name)                 \
        SAVE_PROFILE_INTERVAL_ASSIGNED(); \
        return 0;                         \
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
        const char* CP_FUNC_NAME __attribute__((unused)) = #name;         \
        BEGIN_PROFILE_INTERVAL();                                         \
        ASSIGN_PROFILE_INTERVAL(rs_##name);

#define END_RS_FUNC(name)                 \
        SAVE_PROFILE_INTERVAL_ASSIGNED(); \
        return 0;                         \
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
    ptr_t off;
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
        int ret    = 0;                                                 \
        ptr_t base = store->base;

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

#define DEBUG_RESUME     0
#define DEBUG_CHECKPOINT 0

#if DEBUG_RESUME == 1
#define DEBUG_RS(fmt, ...) \
    debug("GET %s(0x%08lx): " fmt "\n", CP_FUNC_NAME, entry->cp_un.cp_val, ##__VA_ARGS__)
#else
#define DEBUG_RS(...) do {} while (0)
#endif

#include <shim_profile.h>

#define START_MIGRATE(store, name, ...)                                    \
    ({                                                                     \
        int ret = 0;                                                       \
        do {                                                               \
            BEGIN_PROFILE_INTERVAL();                                      \
                                                                           \
            if (!((store)->cp_map = create_cp_map())) {                    \
                ret = -ENOMEM;                                             \
                goto out;                                                  \
            }                                                              \
            SAVE_PROFILE_INTERVAL(checkpoint_create_map);                  \
                                                                           \
            ret = migrate_cp_##name(store, ##__VA_ARGS__);                 \
            if (ret < 0)                                                   \
                goto out;                                                  \
                                                                           \
            SAVE_PROFILE_INTERVAL(checkpoint_copy);                        \
            ADD_PROFILE_OCCURENCE(checkpoint_total_size, (store)->offset); \
            INC_PROFILE_OCCURENCE(checkpoint_count);                       \
                                                                           \
            debug("complete checkpointing data\n");                        \
        out:                                                               \
            destroy_cp_map((store)->cp_map);                               \
            SAVE_PROFILE_INTERVAL(checkpoint_destroy_map);                 \
        } while (0);                                                       \
        ret;                                                               \
    })

struct newproc_cp_header {
    struct cp_header {
        unsigned long size;
        void* addr;
        unsigned long offset;
    } hdr;
    struct mem_header {
        unsigned long entoffset;
        int nentries;
    } mem;
    struct palhdl_header {
        unsigned long entoffset;
        int nentries;
    } palhdl;
};

struct newproc_header {
    struct newproc_cp_header checkpoint;
    int failure;
#ifdef PROFILE
    unsigned long begin_create_time;
    unsigned long create_time;
    unsigned long write_proc_time;
#endif
};

struct newproc_response {
    IDTYPE child_vmid;
    int failure;
};

int do_migration(struct newproc_cp_header* hdr, void** cpptr);
int restore_checkpoint(struct cp_header* cphdr, struct mem_header* memhdr, ptr_t base, ptr_t type);
int do_migrate_process(int (*migrate)(struct shim_cp_store*, struct shim_thread*,
                                      struct shim_process*, va_list),
                       struct shim_handle* exec, const char** argv, struct shim_thread* thread,
                       ...);
int init_from_checkpoint_file(const char* filename, struct newproc_cp_header* hdr, void** cpptr);
int restore_from_file(const char* filename, struct newproc_cp_header* hdr, void** cpptr);
void restore_context(struct shim_context* context);
int create_checkpoint(const char* cpdir, IDTYPE* session);
int join_checkpoint(struct shim_thread* cur, IDTYPE sid);

#endif /* _SHIM_CHECKPOINT_H_ */
