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
 * shim_utils.h
 */

#ifndef _SHIM_UTILS_H_
#define _SHIM_UTILS_H_

#include <api.h>
#include <list.h>
#include <pal.h>
#include <shim_handle.h>
#include <shim_internal.h>

struct shim_handle;

void sysparser_printf(const char* fmt, ...);

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

static inline char* qstrsetstr(struct shim_qstr* qstr, const char* str, size_t size) {
    if (!str) {
        qstrfree(qstr);
        return NULL;
    }

    if (size >= STR_SIZE)
        return NULL;

    char* buf = qstr->name;

    if (size >= QSTR_SIZE) {
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

    memcpy(buf, str, size);
    buf[size] = 0;
    qstr->len = size;

    return buf;
}

static inline char* qstrsetstrs(struct shim_qstr* qstr, int nstrs, const char** strs,
                                size_t* sizes) {
    size_t total_size = 0;

    for (int i = 0; i < nstrs; i++) {
        total_size += sizes[i];
    }

    if (total_size >= STR_SIZE)
        return NULL;

    char* buf = qstr->name;

    if (total_size >= QSTR_SIZE) {
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
        int size = sizes[i];
        memcpy(ptr, strs[i], size);
        ptr[size] = 0;
        qstr->len += size;
        ptr += size;
    }

    return buf;
}

static inline int qstrempty(const struct shim_qstr* qstr) {
    return qstr->len == 0;
}

static inline void qstrcopy(struct shim_qstr* to, const struct shim_qstr* from) {
    qstrsetstr(to, qstrgetstr(from), from->len);
    to->hash = from->hash;
}

static inline int qstrcmpstr(const struct shim_qstr* qstr, const char* str, size_t size) {
    if (qstr->len != size)
        return 1;

    return memcmp(qstrgetstr(qstr), str, size);
}

//#define SLAB_DEBUG_PRINT
//#define SLAB_DEBUG_TRACE

/* heap allocation functions */
int init_slab(void);

#if defined(SLAB_DEBUG_PRINT) || defined(SLAB_DEBUG_TRACE)
void* __malloc_debug(size_t size, const char* file, int line);
#define malloc(size) __malloc_debug(size, __FILE__, __LINE__)
void __free_debug(void* mem, const char* file, int line);
#define free(mem) __free_debug(mem, __FILE__, __LINE__)
void* __malloc_copy_debug(const void* mem, size_t size, const char* file, int line);
#define malloc_copy(mem, size) __malloc_copy_debug(mem, size, __FILE__, __LINE__)
#else
void* malloc(size_t size);
void free(void* mem);
void* malloc_copy(const void* mem, size_t size);
#endif

static_always_inline char* qstrtostr(struct shim_qstr* qstr, bool on_stack) {
    int len   = qstr->len;
    char* buf = on_stack ? __alloca(len + 1) : malloc(len + 1);

    if (!buf)
        return NULL;

    memcpy(buf, qstrgetstr(qstr), len);

    buf[len] = 0;
    return buf;
}

/* typedef a 32 bit type */
#ifndef UINT4
#define UINT4 uint32_t
#endif

/* Data structure for MD5 (Message Digest) computation */
struct shim_md5_ctx {
    UINT4 i[2];               /* number of _bits_ handled mod 2^64 */
    UINT4 buf[4];             /* scratch buffer */
    unsigned char in[64];     /* input buffer */
    unsigned char digest[16]; /* actual digest after MD5Final call */
};

void md5_init(struct shim_md5_ctx* mdContext);
void md5_update(struct shim_md5_ctx* mdContext, const void* buf, size_t len);
void md5_final(struct shim_md5_ctx* mdContext);

/* prompt user for confirmation */
int message_confirm(const char* message, const char* options);

/* ELF binary loading */
int check_elf_object(struct shim_handle* file);
int load_elf_object(struct shim_handle* file, void* addr, size_t mapped);
int load_elf_interp(struct shim_handle* exec);
int free_elf_interp(void);
noreturn void execute_elf_object(struct shim_handle* exec, int* argcp, const char** argp,
                                 elf_auxv_t* auxp);
int remove_loaded_libraries(void);

/* gdb debugging support */
void remove_r_debug(void* addr);
void append_r_debug(const char* uri, void* addr, void* dyn_addr);
void clean_link_map_list(void);

/* create unique files/pipes */
#define PIPE_URI_SIZE 40
int create_pipe(IDTYPE* pipeid, char* uri, size_t size, PAL_HANDLE* hdl, struct shim_qstr* qstr,
                bool use_vmid_for_name);
int create_dir(const char* prefix, char* path, size_t size, struct shim_handle** hdl);
int create_file(const char* prefix, char* path, size_t size, struct shim_handle** hdl);
int create_handle(const char* prefix, char* path, size_t size, PAL_HANDLE* hdl, unsigned int* id);

/* Asynchronous event support */
int init_async(void);
int64_t install_async_event(PAL_HANDLE object, unsigned long time,
                            void (*callback)(IDTYPE caller, void* arg), void* arg);
struct shim_thread* terminate_async_helper(void);

extern struct config_store* root_config;

#endif /* _SHIM_UTILS_H */
