/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2019-2020 Invisible Things Lab
 *                         Rafal Wojdyla <omeg@invisiblethingslab.com>
 * Copyright (C) 2011-2019 Intel Corporation
 */

#ifndef PROTECTED_FILES_INTERNAL_H_
#define PROTECTED_FILES_INTERNAL_H_

#include <limits.h>

#include "assert.h"
#include "list.h"
#include "lru_cache.h"
#include "protected_files.h"

#define PF_FILE_ID       0x46505f4850415247 /* GRAPH_PF */
#define PF_MAJOR_VERSION 0x01
#define PF_MINOR_VERSION 0x00

#pragma pack(push, 1)

typedef struct _metadata_plain {
    uint64_t   file_id;
    uint8_t    major_version;
    uint8_t    minor_version;
    pf_keyid_t metadata_key_id;
    pf_mac_t   metadata_gmac; /* GCM mac */
} metadata_plain_t;

#define PATH_MAX_SIZE (260 + 512)

// these are all defined as relative to node size, so we can decrease node size in tests
// and have deeper tree
#define MD_USER_DATA_SIZE (PF_NODE_SIZE * 3 / 4) // 3072
static_assert(MD_USER_DATA_SIZE == 3072, "bad struct size");

typedef struct _metadata_encrypted {
    char     path[PATH_MAX_SIZE];
    uint64_t size;
    pf_key_t mht_key;
    pf_mac_t mht_gmac;
    uint8_t  data[MD_USER_DATA_SIZE];
} metadata_encrypted_t;

typedef uint8_t metadata_encrypted_blob_t[sizeof(metadata_encrypted_t)];

#define METADATA_NODE_SIZE PF_NODE_SIZE

typedef uint8_t metadata_padding_t[METADATA_NODE_SIZE -
                                   (sizeof(metadata_plain_t) + sizeof(metadata_encrypted_blob_t))];

typedef struct _metadata_node {
    metadata_plain_t          plain_part;
    metadata_encrypted_blob_t encrypted_part;
    metadata_padding_t        padding;
} metadata_node_t;

static_assert(sizeof(metadata_node_t) == PF_NODE_SIZE, "sizeof(metadata_node_t)");

typedef struct _data_node_crypto {
    pf_key_t key;
    pf_mac_t gmac;
} gcm_crypto_data_t;

// for PF_NODE_SIZE == 4096, we have 96 attached data nodes and 32 mht child nodes
// for PF_NODE_SIZE == 2048, we have 48 attached data nodes and 16 mht child nodes
// for PF_NODE_SIZE == 1024, we have 24 attached data nodes and 8 mht child nodes
// 3/4 of the node size is dedicated to data nodes
#define ATTACHED_DATA_NODES_COUNT ((PF_NODE_SIZE / sizeof(gcm_crypto_data_t)) * 3 / 4)
static_assert(ATTACHED_DATA_NODES_COUNT == 96, "ATTACHED_DATA_NODES_COUNT");
// 1/4 of the node size is dedicated to child mht nodes
#define CHILD_MHT_NODES_COUNT ((PF_NODE_SIZE / sizeof(gcm_crypto_data_t)) * 1 / 4)
static_assert(CHILD_MHT_NODES_COUNT == 32, "CHILD_MHT_NODES_COUNT");

typedef struct _mht_node {
    gcm_crypto_data_t data_nodes_crypto[ATTACHED_DATA_NODES_COUNT];
    gcm_crypto_data_t mht_nodes_crypto[CHILD_MHT_NODES_COUNT];
} mht_node_t;

static_assert(sizeof(mht_node_t) == PF_NODE_SIZE, "sizeof(mht_node_t)");

typedef struct _data_node {
    uint8_t data[PF_NODE_SIZE];
} data_node_t;

static_assert(sizeof(data_node_t) == PF_NODE_SIZE, "sizeof(data_node_t)");

typedef struct _encrypted_node {
    uint8_t cipher[PF_NODE_SIZE];
} encrypted_node_t;

static_assert(sizeof(encrypted_node_t) == PF_NODE_SIZE, "sizeof(encrypted_node_t)");

#define MAX_PAGES_IN_CACHE 48

typedef enum {
    FILE_MHT_NODE_TYPE  = 1,
    FILE_DATA_NODE_TYPE = 2,
} mht_node_type_e;

// make sure these are the same size
static_assert(sizeof(mht_node_t) == sizeof(data_node_t),
              "sizeof(mht_node_t) == sizeof(data_node_t)");

DEFINE_LIST(_file_node);
typedef struct _file_node {
    LIST_TYPE(_file_node) list;
    uint8_t type;
    uint64_t node_number;
    struct _file_node* parent;
    bool need_writing;
    bool new_node;
    struct {
        uint64_t physical_node_number;
        encrypted_node_t encrypted; // the actual data from the disk
    };
    union { // decrypted data
        mht_node_t mht;
        data_node_t data;
    } decrypted;
} file_node_t;
DEFINE_LISTP(_file_node);

#pragma pack(pop)

struct pf_context {
    metadata_node_t file_metadata; // actual data from disk's meta data node
    pf_status_t last_error;
    metadata_encrypted_t encrypted_part_plain; // encrypted part of metadata node, decrypted
    file_node_t root_mht; // the root of the mht is always needed (for files bigger than 3KB)
    pf_handle_t file;
    pf_file_mode_t mode;
    uint64_t offset; // current file position (user's view)
    bool end_of_file;
    uint64_t real_file_size;
    bool need_writing;
    pf_status_t file_status;
    pf_key_t user_kdk_key;
    pf_key_t cur_key;
    lruc_context_t* cache;
#ifdef DEBUG
    char* debug_buffer; // buffer for debug output
#endif
};

/* ipf prefix means "Intel protected files", these are functions from the SGX SDK implementation */
static bool ipf_init_fields(pf_context_t* pf);
static bool ipf_init_existing_file(pf_context_t* pf, const char* path);
static bool ipf_init_new_file(pf_context_t* pf, const char* path);

static bool ipf_read_node(pf_context_t* pf, pf_handle_t handle, uint64_t node_number, void* buffer,
                          uint32_t node_size);
static bool ipf_write_node(pf_context_t* pf, pf_handle_t handle, uint64_t node_number, void* buffer,
                           uint32_t node_size);

static bool ipf_import_metadata_key(pf_context_t* pf, bool restore, pf_key_t* output);
static bool ipf_generate_random_key(pf_context_t* pf, pf_key_t* output);
static bool ipf_restore_current_metadata_key(pf_context_t* pf, pf_key_t* output);

static file_node_t* ipf_get_data_node(pf_context_t* pf);
static file_node_t* ipf_read_data_node(pf_context_t* pf);
static file_node_t* ipf_append_data_node(pf_context_t* pf);
static file_node_t* ipf_get_mht_node(pf_context_t* pf);
static file_node_t* ipf_read_mht_node(pf_context_t* pf, uint64_t mht_node_number);
static file_node_t* ipf_append_mht_node(pf_context_t* pf, uint64_t mht_node_number);

static bool ipf_update_all_data_and_mht_nodes(pf_context_t* pf);
static bool ipf_update_metadata_node(pf_context_t* pf);
static bool ipf_write_all_changes_to_disk(pf_context_t* pf);
static bool ipf_internal_flush(pf_context_t* pf);

static pf_context_t* ipf_open(const char* path, pf_file_mode_t mode, bool create, pf_handle_t file,
                              size_t real_size, const pf_key_t* kdk_key, pf_status_t* status);
static bool ipf_close(pf_context_t* pf);
static size_t ipf_read(pf_context_t* pf, void* ptr, size_t size);
static size_t ipf_write(pf_context_t* pf, const void* ptr, size_t size);
static bool ipf_seek(pf_context_t* pf, uint64_t new_offset);
static void ipf_try_clear_error(pf_context_t* pf);

#endif /* PROTECTED_FILES_INTERNAL_H_ */
