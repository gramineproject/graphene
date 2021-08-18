/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#ifndef _SHIM_UTILS_H_
#define _SHIM_UTILS_H_

#include "api.h"
#include "list.h"
#include "pal.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_types.h"
#include "toml.h"

struct shim_handle;

/* quick hash function based on Robert Jenkins' hash algorithm */
static inline uint64_t hash64(uint64_t key) {
    key = (~key) + (key << 21);
    key = key ^ (key >> 24);
    key = (key + (key << 3)) + (key << 8);
    key = key ^ (key >> 14);
    key = (key + (key << 2)) + (key << 4);
    key = key ^ (key >> 28);
    key = key + (key << 31);
    return key;
}

/* string object */
struct shim_str* get_str_obj(void);
int free_str_obj(struct shim_str* str);
int init_str_mgr(void);

/* qstring object */
#define QSTR_INIT \
    { .len = 0, .oflow = NULL }

static inline const char* qstrgetstr(const struct shim_qstr* qstr) {
    return qstr->oflow ? qstr->oflow->str : qstr->name;
}

static inline void qstrfree(struct shim_qstr* qstr) {
    if (qstr->oflow) {
        free_str_obj(qstr->oflow);
        qstr->oflow = NULL;
    }

    qstr->name[0] = 0;
    qstr->len     = 0;
}

static inline char* qstrsetstr(struct shim_qstr* qstr, const char* str, size_t len) {
    if (!str) {
        qstrfree(qstr);
        return NULL;
    }

    if (len >= STR_SIZE)
        return NULL;

    char* buf = qstr->name;

    if (len >= QSTR_SIZE) {
        if (!qstr->oflow) {
            qstr->oflow = get_str_obj();
            if (!qstr->oflow)
                return NULL;
        }
        buf = qstr->oflow->str;
    } else {
        if (qstr->oflow) {
            free_str_obj(qstr->oflow);
            qstr->oflow = NULL;
        }
    }

    memcpy(buf, str, len);
    buf[len] = 0;
    qstr->len = len;

    return buf;
}

static inline char* qstrsetstrs(struct shim_qstr* qstr, int nstrs, const char** strs,
                                size_t* lengths) {
    size_t total_len = 0;

    for (int i = 0; i < nstrs; i++) {
        total_len += lengths[i];
    }

    if (total_len >= STR_SIZE)
        return NULL;

    char* buf = qstr->name;

    if (total_len >= QSTR_SIZE) {
        if (!qstr->oflow) {
            // TODO: alloc proper size.
            qstr->oflow = get_str_obj();
            if (!qstr->oflow)
                return NULL;
        }
        buf = qstr->oflow->str;
    }

    char* ptr = buf;
    qstr->len = 0;

    for (int i = 0; i < nstrs; i++) {
        size_t len = lengths[i];
        memcpy(ptr, strs[i], len);
        ptr[len] = 0;
        qstr->len += len;
        ptr += len;
    }

    return buf;
}

static inline int qstrempty(const struct shim_qstr* qstr) {
    return qstr->len == 0;
}

static inline void qstrcopy(struct shim_qstr* to, const struct shim_qstr* from) {
    qstrsetstr(to, qstrgetstr(from), from->len);
}

static inline int qstrcmpstr(const struct shim_qstr* qstr, const char* str, size_t len) {
    if (qstr->len != len)
        return 1;

    return memcmp(qstrgetstr(qstr), str, len);
}

/* heap allocation functions */
int init_slab(void);

void* malloc(size_t size);
void free(void* mem);
void* malloc_copy(const void* mem, size_t size);

/* ELF binary loading */
struct link_map;
int init_elf_objects(void);
int check_elf_object(struct shim_handle* file);
int load_elf_object(struct shim_handle* file, struct link_map** out_map);
int load_elf_interp(struct link_map* exec_map);
noreturn void execute_elf_object(struct link_map* exec_map, void* argp, elf_auxv_t* auxp);
void remove_loaded_elf_objects(void);
int init_brk_from_executable(struct link_map* exec_map);
int register_library(const char* name, unsigned long load_address);

/* gdb debugging support */
int init_r_debug(void);
void remove_r_debug(void* addr);
void append_r_debug(const char* uri, void* addr);
void clean_link_map_list(void);

/* Get the IPC pipe uri associated with `vmid`. */
int vmid_to_uri(IDTYPE vmid, char* uri, size_t uri_len);

/* create unique files/pipes */
int create_pipe(char* name, char* uri, size_t size, PAL_HANDLE* hdl, struct shim_qstr* qstr,
                bool use_vmid_for_name);

/* Asynchronous event support */
int init_async_worker(void);
int64_t install_async_event(PAL_HANDLE object, unsigned long time,
                            void (*callback)(IDTYPE caller, void* arg), void* arg);
struct shim_thread* terminate_async_worker(void);

extern const toml_table_t* g_manifest_root;

int read_exact(PAL_HANDLE handle, void* buf, size_t size);
int write_exact(PAL_HANDLE handle, void* buf, size_t size);

static inline uint64_t timespec_to_us(const struct __kernel_timespec* ts) {
    return ts->tv_sec * TIME_US_IN_S + ts->tv_nsec / TIME_NS_IN_US;
}

#endif /* _SHIM_UTILS_H */
