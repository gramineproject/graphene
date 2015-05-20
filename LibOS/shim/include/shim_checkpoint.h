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
 * shim_checkpoints.c
 *
 * This file contains definitions and macros for checkpointing method.
 */

#ifndef _SHIM_CHECKPOINT_H_
#define _SHIM_CHECKPOINT_H_

#include <shim_defs.h>
#include <shim_ipc.h>
#include <shim_profile.h>

#include <pal.h>

#include <stdarg.h>

#ifdef __i386__
typedef uint32_t ptr_t;
# define hashfunc hash32
#else
typedef uint64_t ptr_t;
# define hashfunc hash64
#endif

#define __attribute_migratable __attribute__((section(".migratable")))

extern char __migratable;
extern char __migratable_end;

/* TSAI 7/11/2012:
   The migration scheme we are expecting is to support an easy syntax to
   implement migration procedure. A migration procedure can be written
   in teh following syntax:

   BEGIN_MIGRATE_DEFINITION(exec)
   {
       DEFINE_MIGRATE(thread, );
       DEFINE_MIGRATE(handle_map, );
   }
   void *checkpoint = DO_MIGRATE(exec);

   The structure of checkpoint data will be a counting-down stack-like
   memory segment, with enough space reserved below for 1. in case the
   dry run miscalculate the checkpoint size or 2. stack use for the new
   thread.

   Below is the figure for our checkpoint structure:

   (later added by PAL:  argc        program arguments
                         argv[0]
                         argv[1]
                         ...
                         envp[0]     env variables
                         envp[1]
                         ...
                         NULL-end
                         auxv[0]     aux vectors
                         auxv[1]
                         ...
                         auxv[n]     AT_NULL
   Low Bytes -------------------------------------------------
                checkpoint base (identified by a magic number)
             -------------------------------------------------
                checkpoint_entry[0]
                checkpoint_entry[1]
                checkpoint_entry[2]
                ...
                checkpoint_entry[n]  CP_NULL
              ------------------------------------------------
                data section for checkpoint 0
                data section for checkpoint 1
                data section for checkpoint 2
                ...
                data section for checkpoint n-1
   High Bytes ------------------------------------------------


*/

struct shim_cp_entry
{
    ptr_t cp_type;  /* entry type */
    union
    {
        ptr_t cp_val;   /* interger value */
        /* orignally there is a pointer, now we don't need them */
    } cp_un;
};

struct shim_gipc_entry {
    struct shim_gipc_entry * next;
    enum { ABS_ADDR, REL_ADDR, ANY_ADDR } addr_type;
    void * addr;
    int npages;
    int prot;
    struct shim_vma * vma;
#if HASH_GIPC == 1
    unsigned long first_hash;
#endif
};

#define SET_GIPC_REL_ADDR(gipc)                                             \
    do {                                                                    \
         (gipc)->addr_type = REL_ADDR;                                      \
         (gipc)->addr = (void *) ((gipc)->addr - (void *) &__load_address); \
    } while (0)

struct shim_mem_entry {
    void * addr;
    int size;
    int prot;
    bool need_alloc, need_prot;
    struct shim_vma * vma;
    void * data;
};

struct shim_cp_store {
    void * cpaddr;
    void * cpdata;
    size_t cpsize;
    void * addr_map;
    bool use_gipc;
    struct shim_gipc_entry * gipc_entries, * gipc_entries_tail;
    int gipc_nentries;
};

#define INIT_CP_STORE_GIPC(store)                       \
    do {                                                \
        (store)->use_gipc = false;                      \
        (store)->gipc_entries = NULL;                   \
        (store)->gipc_entries_tail = NULL;              \
        (store)->gipc_nentries = 0;                     \
    } while (0)

#define INIT_CP_STORE(store)                            \
    do {                                                \
        (store)->cpaddr = NULL;                         \
        (store)->cpdata = NULL;                         \
        (store)->cpsize = 0;                            \
        (store)->addr_map = create_addr_map();          \
        INIT_CP_STORE_GIPC(store);                      \
    } while (0)

#define MIGRATE_FUNC_ARGS                                                   \
    struct shim_cp_store * store, struct shim_cp_entry ** ent, ptr_t base,  \
    unsigned long * offset, void * obj, size_t size, void ** objp,          \
    bool recursive, bool dry

#define MIGRATE_FUNC_RET size_t

#define RESUME_FUNC_ARGS                                                    \
    struct shim_cp_entry ** ent, ptr_t base, size_t cpsize, long cprebase

#define RESUME_FUNC_RET int

typedef MIGRATE_FUNC_RET (*migrate_func) (MIGRATE_FUNC_ARGS);
typedef RESUME_FUNC_RET (*resume_func) (RESUME_FUNC_ARGS);

extern const char *       __migrate_name;
extern const migrate_func __migrate_func;
extern const resume_func  __resume_func;

#define CP_NULL   0
#define CP_IGNORE 1
#define CP_BASE   2
#define CP_ADDR   3
#define CP_SIZE   4
#define CP_PID    5
#define CP_UID    6
#define CP_GID    7
#define CP_FD     8
#define CP_BOOL   9
#define CP_PALHDL 10

#define CP_FUNC_BASE   11

#define CP_FUNC_INDEX(name)                                             \
    ({  extern const migrate_func migrate_func_##name;                  \
        &migrate_func_##name - &__migrate_func;  })

#define CP_FUNC(name)   CP_FUNC_BASE + CP_FUNC_INDEX(name)
#define CP_FUNC_NAME(type)      (&__migrate_name)[(type) - CP_FUNC_BASE]

#define ADD_ENTRY(type, value)                                      \
    do {                                                            \
        USED += sizeof(struct shim_cp_entry);                       \
        if (!dry) {                                                 \
            struct shim_cp_entry * tmp = (*ent)++;                  \
            tmp->cp_type = CP_##type;                               \
            tmp->cp_un.cp_val = (ptr_t) (value);                    \
                                                                    \
            if (DEBUG_CHECKPOINT)                                   \
                debug("ADD CP_" #type "(%p) :%d\n",                 \
                      tmp->cp_un.cp_val,                            \
                      tmp - (struct shim_cp_entry *) base);         \
        } else {                                                    \
            if (DEBUG_CHECKPOINT)                                   \
                debug("(dry) ADD CP_" #type "\n");                  \
        }                                                           \
    } while(0)

#define ADD_OFFSET(size)                                            \
    ({                                                              \
        int _size = ((size) + 7) & ~7;                              \
        USED += _size;                                              \
        if (!dry)                                                   \
            *offset -= _size;                                       \
        if (DEBUG_CHECKPOINT)                                       \
            debug("%sADD OFFSET(%d)\n",                             \
                  dry ? "(dry) " : "", _size);                      \
        dry ? 0 : *offset;                                          \
    })

#define ADD_FUNC_ENTRY(value)                                       \
    do {                                                            \
        USED += sizeof(struct shim_cp_entry);                       \
        if (!dry) {                                                 \
            struct shim_cp_entry * tmp = (*ent)++;                  \
            tmp->cp_type = CP_FUNC_TYPE;                            \
            tmp->cp_un.cp_val = (ptr_t) value;                      \
                                                                    \
            if (DEBUG_CHECKPOINT)                                   \
                debug("ADD CP_FUNC_%s(%p) :%d\n", CP_FUNC_NAME,     \
                      tmp->cp_un.cp_val,                            \
                      tmp - (struct shim_cp_entry *) base);         \
        } else {                                                    \
            if (DEBUG_CHECKPOINT)                                   \
                debug("(dry) ADD CP_FUNC_%s\n", CP_FUNC_NAME);      \
        }                                                           \
    } while(0)


#define GET_ENTRY(type)                                             \
    ({  struct shim_cp_entry * tmp = (*ent)++;                      \
                                                                    \
        while (tmp->cp_type != CP_##type)                           \
            tmp = (*ent)++;                                         \
                                                                    \
        /* debug("GET CP_" #type "(%p) :%d\n",                      \
                 tmp->cp_un.cp_val,                                 \
                 tmp - (struct shim_cp_entry *) base); */           \
                                                                    \
        tmp->cp_un.cp_val;                                          \
     })

#define GET_FUNC_ENTRY()                                            \
    ({  struct shim_cp_entry * tmp = (*ent)++;                      \
                                                                    \
        while (tmp->cp_type != CP_FUNC_TYPE)                        \
            tmp = (*ent)++;                                         \
                                                                    \
        /* debug("GET CP_FUNC_%s(%p) :%d\n", CP_FUNC_NAME,          \
                 tmp->cp_un.cp_val,                                 \
                 tmp - (struct shim_cp_entry *) base); */           \
                                                                    \
        tmp->cp_un.cp_val;                                          \
     })


#define DEFINE_MIGRATE_FUNC(name)                                   \
    const char * migrate_name_##name                                \
        __attribute__((section(".migrate_name." #name))) = #name;   \
                                                                    \
    extern MIGRATE_FUNC_RET migrate_##name (MIGRATE_FUNC_ARGS);     \
    const migrate_func migrate_func_##name                          \
        __attribute__((section(".migrate." #name))) = &migrate_##name;\
                                                                    \
    extern RESUME_FUNC_RET resume_##name (RESUME_FUNC_ARGS);        \
    const resume_func resume_func_##name                            \
        __attribute__((section(".resume." #name))) = &resume_##name;\
                                                                    \
    DEFINE_PROFILE_INTERVAL(migrate_##name, migrate_func);          \
    DEFINE_PROFILE_INTERVAL(resume_##name,  resume_func);           \


#define MIGRATE_FUNC_BODY(name)                                 \
    MIGRATE_FUNC_RET migrate_##name (MIGRATE_FUNC_ARGS)         \
    {                                                           \
        int CP_FUNC_TYPE __attribute__((unused))                \
                                    = CP_FUNC(name);            \
        const char * CP_FUNC_NAME __attribute__((unused))       \
                                    = #name;                    \
        size_t USED = 0;                                        \
        BEGIN_PROFILE_INTERVAL();                               \
        ASSIGN_PROFILE_INTERVAL(migrate_##name);

#define END_MIGRATE_FUNC                                        \
        if (!dry) SAVE_PROFILE_INTERVAL_ASSIGNED();             \
        return USED;                                            \
    }


#define RESUME_FUNC_BODY(name)                                  \
    RESUME_FUNC_RET resume_##name (RESUME_FUNC_ARGS)            \
    {                                                           \
        int CP_FUNC_TYPE __attribute__((unused))                \
                                    = CP_FUNC(name);            \
        const char * CP_FUNC_NAME __attribute__((unused))       \
                                    = #name;                    \
        BEGIN_PROFILE_INTERVAL();                               \
        ASSIGN_PROFILE_INTERVAL(resume_##name);

#define END_RESUME_FUNC \
        SAVE_PROFILE_INTERVAL_ASSIGNED();                       \
        return 0;                                               \
    }

#define RESUME_REBASE(obj)                                      \
    do {                                                        \
        void * _ptr = &(obj);                                   \
        size_t _size = sizeof(obj);                             \
        void ** _p;                                             \
        for (_p = _ptr ; _p < (void **)(_ptr + _size) ; _p++)   \
            if (*_p)                                            \
                *_p += cprebase;                                \
    } while (0)


struct shim_addr_map {
    ptr_t addr;
    unsigned long offset;
    size_t size;
};

void * create_addr_map (void);
void destroy_addr_map (void * map);

struct shim_addr_map *
get_addr_map_entry (void * map, ptr_t addr, size_t size, bool create);

#define DO_MIGRATE_SIZE(name, obj, size, objp, recur)                       \
    do {                                                                    \
        extern MIGRATE_FUNC_RET migrate_##name (MIGRATE_FUNC_ARGS);         \
                                                                            \
        USED += migrate_##name (store, ent, base, offset,                   \
                  obj, size, (void **) objp, recur, dry);                   \
    } while (0)


#define __DO_MIGRATE(name, obj, objp, recur)                                \
    do {                                                                    \
        extern MIGRATE_FUNC_RET migrate_##name (MIGRATE_FUNC_ARGS);         \
                                                                            \
        USED += migrate_##name (store, ent, base, offset,                   \
                  obj, sizeof(*(obj)), (void **) objp, recur, dry);         \
    } while (0)

#define DO_MIGRATE_MEMBER(name, obj, newobj, member, recur)                 \
    do {                                                                    \
        typeof(obj->member) *(objp) = (newobj) ?                            \
                                      &(newobj)->member : NULL;             \
                                                                            \
        DO_MIGRATE(name, (obj)->member, (objp), (recur));                   \
    } while (0);

#define DO_MIGRATE(name, obj, objp, recur)                                  \
    do {                                                                    \
        if (!obj)                                                           \
            break;                                                          \
                                                                            \
        struct shim_addr_map * _e = get_addr_map_entry (store->addr_map,    \
                                (ptr_t) (obj), sizeof(*(obj)), 0);          \
                                                                            \
        if (_e && !ENTRY_JUST_CREATED(_e->offset) && !(recur))              \
        {                                                                   \
            if (!dry && objp)                                               \
                *((typeof(obj) *) objp) = (typeof(obj))                     \
                                          (base + _e->offset);              \
            break;                                                          \
        }                                                                   \
                                                                            \
        if (dry ? !_e || (recur) : _e != NULL)                              \
            __DO_MIGRATE(name, (obj), (objp), (recur));                     \
    } while (0)

#define DO_MIGRATE_MEMBER_IF_RECURSIVE(name, obj, newobj, member, recur)    \
    do {                                                                    \
        typeof(obj->member) *(objp) = (newobj) ?                            \
                                      &(newobj)->member : NULL;             \
                                                                            \
        DO_MIGRATE_IF_RECURSIVE(name, (obj)->member, (objp), (recur));      \
    } while (0);

#define DO_MIGRATE_IF_RECURSIVE(name, obj, objp, recur)                     \
    do {                                                                    \
        extern MIGRATE_FUNC_RET migrate_##name (MIGRATE_FUNC_ARGS);         \
        if (!obj)                                                           \
            break;                                                          \
                                                                            \
        struct shim_addr_map * _e = get_addr_map_entry (store->addr_map,    \
                                (ptr_t) (obj), sizeof(*(obj)), 0);          \
                                                                            \
        if (!_e && !recursive)                                              \
        {                                                                   \
            if (!dry && objp) *objp = NULL;                                 \
            break;                                                          \
        }                                                                   \
                                                                            \
        if (_e && !ENTRY_JUST_CREATED(_e->offset) && !(recur))              \
        {                                                                   \
            if (!dry && objp)                                               \
                *((typeof(obj) *) objp) = (typeof(obj))                     \
                                          (base + _e->offset);              \
            break;                                                          \
        }                                                                   \
                                                                            \
        /* 3 condition we need to run a recursive search                    \
               _e && !recursive && dry && recur                             \
               !_e && recursive && dry                                      \
               _e && !dry               */                                  \
        if (dry ?                                                           \
            (_e ? !recursive && (recur) : recursive) : _e != NULL)          \
                __DO_MIGRATE(name, (obj), (objp), (recur));                 \
    } while (0)

#define DO_MIGRATE_IN_MEMBER(name, obj, newobj, member, recur)              \
    __DO_MIGRATE(name, dry ? &(obj)->member : &(newobj)->member,            \
                 NULL, (recur))

#define CHECKPOINT_ADDR (NULL)

#define MAP_UNALLOCATED 0x8000000000000000
#define MAP_UNASSIGNED  0x4000000000000000
#define MAP_UNUSABLE (MAP_UNALLOCATED|MAP_UNASSIGNED)

#define ENTRY_JUST_CREATED(off) (off & MAP_UNUSABLE)

static inline __attribute__((always_inline))
ptr_t add_to_migrate_map (void * map, void * obj, ptr_t off,
                          size_t size, bool dry)
{
    struct shim_addr_map * e = get_addr_map_entry(map,
                    (ptr_t) obj, size, 1);

    ptr_t result = e->offset;
    if (dry) {
        if (result & MAP_UNALLOCATED)
            e->offset = MAP_UNASSIGNED;
        else
            result = 0;
    } else {
        if (result & MAP_UNUSABLE) {
            assert(size);
            assert(off >= size);
            e->offset = off - size;
            e->size = size;
        }
    }

    return result;
}

#define ADD_TO_MIGRATE_MAP(obj, off, size) \
        add_to_migrate_map(store->addr_map, (obj), dry ? 0 : (off), (size), dry)

#define MIGRATE_DEF_ARGS    \
        struct shim_cp_store * store, void * data, size_t size, bool dry

#define BEGIN_MIGRATION_DEF(name, ...)                                  \
    auto size_t migrate_def_##name (MIGRATE_DEF_ARGS, ##__VA_ARGS__)    \
    {                                                                   \
        size_t USED = 0;                                                \
        unsigned long offset = size;                                    \
        struct shim_cp_entry * ENTRY = (struct shim_cp_entry *) data;   \
        struct shim_cp_entry * *ent = &ENTRY;                           \
        uintptr_t base = (uintptr_t) data;


#define END_MIGRATION_DEF                                       \
        ADD_ENTRY(NULL, 0);                                     \
        return USED;                                            \
    }


#define DEFINE_MIGRATE(name, obj, size, recursive)                          \
    do {                                                                    \
        extern MIGRATE_FUNC_RET migrate_##name (MIGRATE_FUNC_ARGS);         \
                                                                            \
        USED += migrate_##name(store, ent, dry ? 0 : base,                  \
                  dry ? 0 : &offset, (obj), (size), NULL, recursive, dry);  \
    } while (0)

#define DEBUG_RESUME      0
#define DEBUG_CHECKPOINT  0

#ifndef malloc_method
#define malloc_method(size) system_malloc(size)
#endif

#include <shim_profile.h>

#define START_MIGRATE(store, name, preserve, ...)                           \
    ({  int _ret = 0;                                                       \
        do {                                                                \
            size_t size;                                                    \
            void * data;                                                    \
                                                                            \
            BEGIN_PROFILE_INTERVAL();                                       \
                                                                            \
            size = migrate_def_##name((store), NULL, 0, true, ##__VA_ARGS__) \
                   + (preserve);                                            \
            SAVE_PROFILE_INTERVAL(checkpoint_predict_size);                 \
            ADD_PROFILE_OCCURENCE(checkpoint_total_size, size);             \
            INC_PROFILE_OCCURENCE(checkpoint_count);                        \
                                                                            \
            data = malloc_method(size);                                     \
            SAVE_PROFILE_INTERVAL(checkpoint_alloc_memory);                 \
            debug("allocate checkpoint: %p\n", data);                       \
                                                                            \
            if (!data) {                                                    \
                destroy_addr_map((store)->addr_map);                        \
                (store)->addr_map = NULL;                                   \
                SAVE_PROFILE_INTERVAL(checkpoint_destroy_addr_map);         \
                _ret = -ENOMEM;                                             \
                break;                                                      \
            }                                                               \
            (store)->cpaddr = data;                                         \
            (store)->cpdata = data + (preserve);                            \
            (store)->cpsize = size;                                         \
                                                                            \
            migrate_def_##name((store), data + (preserve), size - (preserve), \
                               false, ##__VA_ARGS__);                       \
            SAVE_PROFILE_INTERVAL(checkpoint_copy_object);                  \
            debug("complete checkpointing data\n");                         \
                                                                            \
            destroy_addr_map((store)->addr_map);                            \
            SAVE_PROFILE_INTERVAL(checkpoint_destroy_addr_map);             \
        } while (0);                                                        \
        _ret; })

struct newproc_cp_header {
    struct cp_header {
        unsigned long cpsize;
        void * cpaddr;
        unsigned long cpoffset;
    } data;
    struct gipc_header {
        PAL_NUM gipc_key;
        unsigned long gipc_entoffset;
        int gipc_nentries;
    } gipc;
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

int do_migration (struct newproc_cp_header * hdr, void ** cpptr);

int restore_checkpoint (void * cpdata, struct cp_header * hdr, int type);
int restore_gipc (PAL_HANDLE gipc, struct gipc_header * hdr, void * cpdata,
                  long cprebase);
int send_checkpoint_by_gipc (PAL_HANDLE gipc_store,
                             struct shim_cp_store * cpstore);
int send_handles_on_stream (PAL_HANDLE stream, void * cpdata);

int do_migrate_process (int (*migrate) (struct shim_cp_store *,
                                        struct shim_process *,
                                        struct shim_thread *, va_list),
                        struct shim_handle * exec, const char ** argv,
                        struct shim_thread * thread, ...);

int init_from_checkpoint_file (const char * filename,
                               struct newproc_cp_header * hdr,
                               void ** cpptr);
int restore_from_file (const char * filename, struct newproc_cp_header * hdr,
                       void ** cpptr);

void restore_context (struct shim_context * context);

#define CHECKPOINT_REQUESTED        ((IDTYPE) -1)

int create_checkpoint (const char * cpdir, IDTYPE * session);
int join_checkpoint (struct shim_thread * cur, ucontext_t * context);

#endif /* _SHIM_CHECKPOINT_H_ */
