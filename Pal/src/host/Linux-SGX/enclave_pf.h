/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2019-2020 Invisible Things Lab
 *                         Rafal Wojdyla <omeg@invisiblethingslab.com>
 * Copyright (C) 2021      Intel Corporation */

/* Protected files (PF) are encrypted on disk and transparently decrypted when accessed by Graphene
 * or by app running inside Graphene. Internal protected file format was ported from Intel SGX SDK,
 * https://github.com/intel/linux-sgx/tree/1eaa4551d4b02677eec505684412dc288e6d6361/sdk/protected_fs
 *
 * Features:
 * - Data is encrypted (confidentiality) and integrity protected (tamper resistance).
 * - File swap protection (a PF can only be accessed when in a specific path).
 * - Transparency (Graphene app sees PFs as regular files, no need to modify the app).
 *
 * Limitations:
 * - Metadata currently limits PF path size to 512 bytes and filename size to 260 bytes.
 * - Truncating protected files is not yet implemented.
 * - The recovery file feature is disabled (present in Intel SGX SDK).
 */

#ifndef ENCLAVE_PF_H_
#define ENCLAVE_PF_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "api.h"
#include "pal.h"
#include "pal_internal.h"
#include "protected_files.h"

/* Used to track map buffers for protected files */
DEFINE_LIST(pf_map);
struct pf_map {
    LIST_TYPE(pf_map) list;
    struct protected_file* pf;
    void* buffer;
    uint64_t size;
    uint64_t offset; /* offset in PF, needed for write buffers when flushing to the PF */
};
DEFINE_LISTP(pf_map);

/* List of PF map buffers; this list is traversed on PF flush (on file close) */
extern LISTP_TYPE(pf_map) g_pf_map_list;

/* Data of a protected file */
struct protected_file {
    UT_hash_handle hh;
    size_t path_len;
    char* path;
    pf_context_t* context; /* NULL until PF is opened */
    int64_t refcount; /* used for deciding when to call unload_protected_file() */
    int writable_fd; /* fd of underlying file for writable PF, -1 if no writable handles are open */
};

/* Take ownership of the global PF lock */
void pf_lock(void);

/* Release ownership of the global PF lock */
void pf_unlock(void);

/* Set new wrap key for protected files (e.g., provisioned by remote user) */
int set_protected_files_key(const char* pf_key_hex);

/* Return a registered PF that matches specified path
   (or the path is contained in a registered PF directory) */
struct protected_file* get_protected_file(const char* path);

/* Load and initialize a PF (must be called before any I/O operations)
 *
 * path:   normalized host path
 * fd:     pointer to an opened file descriptor (must point to a valid value for the whole time PF
 *         is being accessed)
 * size:   underlying file size (in bytes)
 * mode:   access mode
 * create: if true, the PF is being created/truncated
 * pf:     (optional) PF pointer if already known
 */
struct protected_file* load_protected_file(const char* path, int* fd, size_t size,
                                           pf_file_mode_t mode, bool create,
                                           struct protected_file* pf);

/* Flush PF map buffers and optionally remove and free them.
   If pf is NULL, process all maps containing given buffer.
   If buffer is NULL, process all maps for given pf. */
int flush_pf_maps(struct protected_file* pf, void* buffer, bool remove);

/* Flush map buffers and unload/close the PF */
int unload_protected_file(struct protected_file* pf);

/* Find registered PF by path (exact match) */
struct protected_file* find_protected_file(const char* path);

/* Find protected file by handle (uses handle's path to call find_protected_file) */
struct protected_file* find_protected_file_handle(PAL_HANDLE handle);

/* Initialize the PF library, register PFs from the manifest */
int init_protected_files(void);

#endif /* ENCLAVE_PF_H_ */
