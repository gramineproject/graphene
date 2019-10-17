/* Copyright (C) 2018,2019 Invisible Things Lab
                           Rafal Wojdyla <omeg@invisiblethingslab.com>

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

#include <string.h>
#include "protected_files.h"

/* We can't include stdio.h in Graphene */
int snprintf(char* str, size_t size, const char* format, ...);

/* Callbacks */
static pf_malloc_f   cb_malloc   = NULL;
static pf_free_f     cb_free     = NULL;
static pf_map_f      cb_map      = NULL;
static pf_unmap_f    cb_unmap    = NULL;
static pf_truncate_f cb_truncate = NULL;
static pf_flush_f    cb_flush    = NULL;
static pf_debug_f    cb_debug    = NULL;

static pf_crypto_aes_gcm_encrypt_f cb_crypto_aes_gcm_encrypt = NULL;
static pf_crypto_aes_gcm_decrypt_f cb_crypto_aes_gcm_decrypt = NULL;
static pf_crypto_random_f          cb_crypto_random          = NULL;

/* Debug print without function name prefix. Implicit param: pf (context pointer). */
#define __DEBUG_PF(format, ...) \
    do { \
        if (cb_debug) { \
            snprintf(pf->debug_buffer, PF_DEBUG_PRINT_SIZE_MAX, format, ##__VA_ARGS__); \
            cb_debug(pf->debug_buffer); \
        } \
    } while(0)

/* Debug print with function name prefix. Implicit param: pf (context pointer). */
#define DEBUG_PF(format, ...) \
    do { \
        if (cb_debug) { \
            snprintf(pf->debug_buffer, PF_DEBUG_PRINT_SIZE_MAX, "%s: " format, __FUNCTION__, ##__VA_ARGS__); \
            cb_debug(pf->debug_buffer); \
        } \
    } while(0)

/* Debug print buffer as hex byte values. */
void __hexdump(const void* data, size_t size) {
    if (!cb_debug)
        return;

    const char* digits = "0123456789abcdef";
    uint8_t* ptr = (uint8_t*)data;
    char b[3];

    for (size_t i = 0; i < size; i++) {
        b[0] = digits[ptr[i] / 16];
        b[1] = digits[ptr[i] % 16];
        b[2] = 0;
        cb_debug(b);
    }
}

#define HEXDUMP(x) __hexdump((void*)&(x), sizeof(x))

/* nl suffix: add new line at the end */
#define __HEXDUMPNL(data, size) { if (cb_debug) { __hexdump(data, size); __DEBUG_PF("\n"); } }
#define HEXDUMPNL(x) __HEXDUMPNL((void*)&(x), sizeof(x))

void pf_set_callbacks(pf_malloc_f malloc_f, pf_free_f free_f, pf_map_f map_f, pf_unmap_f unmap_f,
                      pf_truncate_f truncate_f, pf_flush_f flush_f, pf_debug_f debug_f) {
    cb_malloc   = malloc_f;
    cb_free     = free_f;
    cb_map      = map_f;
    cb_unmap    = unmap_f;
    cb_truncate = truncate_f;
    cb_flush    = flush_f;
    cb_debug    = debug_f;
}

void pf_set_crypto_callbacks(pf_crypto_aes_gcm_encrypt_f crypto_aes_gcm_encrypt_f,
                             pf_crypto_aes_gcm_decrypt_f crypto_aes_gcm_decrypt_f,
                             pf_crypto_random_f crypto_random_f) {
    cb_crypto_aes_gcm_encrypt = crypto_aes_gcm_encrypt_f;
    cb_crypto_aes_gcm_decrypt = crypto_aes_gcm_decrypt_f;
    cb_crypto_random = crypto_random_f;
}

static pf_status_t check_callbacks() {
    return (cb_malloc != NULL &&
            cb_free != NULL &&
            cb_map != NULL &&
            cb_unmap != NULL &&
            cb_truncate != NULL &&
            cb_flush != NULL &&
            cb_crypto_aes_gcm_encrypt != NULL &&
            cb_crypto_aes_gcm_decrypt != NULL &&
            cb_crypto_random != NULL) ? PF_STATUS_SUCCESS : PF_STATUS_UNINITIALIZED;
}

/* All internal functions assume that callbacks are initialized and parameters are validated. */

static bool has_mode(pf_context_t* pf, pf_file_mode_t mode) {
    return ((pf->mode & mode) == mode);
}

/* (Public) Check access mode */
pf_status_t pf_has_mode(pf_context_t* pf, pf_file_mode_t mode, bool* result) {
    assert(pf && pf->header);
    pf_status_t pfs = check_callbacks();
    if (PF_FAILURE(pfs))
        goto out;

    pfs = PF_STATUS_SUCCESS;
out:
    if (PF_SUCCESS(pfs))
        *result = has_mode(pf, mode);
    return pfs;
}

/* (Public) Get data size */
pf_status_t pf_get_size(pf_context_t* pf, uint64_t* size) {
    assert(pf->header);
    pf_status_t pfs = check_callbacks();
    if (PF_FAILURE(pfs))
        goto out;

    pfs = PF_STATUS_SUCCESS;
out:
    if (PF_SUCCESS(pfs))
        *size = pf->header->data_size;
    else
        *size = 0;
    return pfs;
}

/* (Public) Check if a path is allowed */
pf_status_t pf_check_path(pf_context_t* pf, const char* path, bool* result) {
    assert(pf && pf->header);
    pf_status_t pfs = check_callbacks();
    if (PF_FAILURE(pfs))
        goto out;

    /* TODO: multiple paths */
    /* allowed_paths should contain at least one NULL-terminated string */
    pfs = PF_STATUS_BAD_HEADER;
    if (pf->header->allowed_paths_size < 1)
        goto out;

    pfs = PF_STATUS_SUCCESS;
    *result = true;

    if (strlen(path) != pf->header->allowed_paths_size - 1)
        *result = false;

    if (memcmp(path, pf->header->allowed_paths, strlen(path)) != 0)
        *result = false;

out:
    return pfs;
}

/* (Internal) Map header and verify its integrity */
static pf_status_t map_header(pf_context_t* pf, size_t underlying_size) {
    pf_status_t status = PF_STATUS_BAD_HEADER;

    DEBUG_PF("pf %p, underlying size %lu\n", pf, underlying_size);

    if (underlying_size < PF_HEADER_SIZE)
        goto out;

    status = cb_map(pf->handle, pf->mode, 0, PF_HEADER_SIZE, (void**)&pf->header);
    if (PF_FAILURE(status))
        goto out;

    pf_header_t* hdr = pf->header;
    DEBUG_PF("version %u, data size %lu, iv ", hdr->version, hdr->data_size);
    HEXDUMPNL(hdr->header_iv);

    status = PF_STATUS_BAD_VERSION;
    if (hdr->version != PF_FORMAT_VERSION)
        goto out;

    status = PF_STATUS_BAD_HEADER;
    if (hdr->data_size > 0) {
        if (underlying_size != PF_CHUNK_OFFSET(PF_CHUNKS_COUNT(hdr->data_size))) {
            DEBUG_PF("invalid underlying size, expected %lu\n",
                     PF_CHUNK_OFFSET(PF_CHUNKS_COUNT(hdr->data_size)));
            goto out;
        }
    } else {
        /* empty file = no chunks */
        if (underlying_size != PF_HEADER_SIZE) {
            DEBUG_PF("invalid underlying size, expected %u\n", PF_HEADER_SIZE);
            goto out;
        }
    }

    status = PF_STATUS_PATH_TOO_LONG;
    if (hdr->allowed_paths_size > PF_HEADER_ALLOWED_PATHS_SIZE) {
        DEBUG_PF("invalid allowed_paths_size %u\n", hdr->allowed_paths_size);
        goto out;
    }

    /* Check header integrity */
    uint8_t tag[PF_MAC_SIZE];

    status = cb_crypto_aes_gcm_encrypt(pf->key, PF_WRAP_KEY_SIZE, hdr->header_iv, PF_IV_SIZE,
                                       hdr, PF_HEADER_SIZE - PF_MAC_SIZE, /* aad */
                                       NULL, 0, /* no data to encrypt */
                                       NULL, /* no output, calc MAC only */
                                       tag, PF_MAC_SIZE);

    if (PF_FAILURE(status)) {
        DEBUG_PF("calculating header MAC failed: %d\n", status);
        goto out;
    }

    status = PF_STATUS_MAC_MISMATCH;
    if (memcmp(tag, hdr->header_mac, PF_MAC_SIZE) != 0) {
        DEBUG_PF("MAC mismatch: ");
        HEXDUMP(tag);
        __DEBUG_PF(" vs expected ");
        __HEXDUMPNL(hdr->header_mac, PF_MAC_SIZE);
        goto out;
    }

    status = PF_STATUS_SUCCESS;

out:
    if (pf->header && PF_FAILURE(status)) {
        if (PF_FAILURE(cb_unmap(pf->header, PF_HEADER_SIZE)))
            DEBUG_PF("(failure path) header unmap failed\n");
        pf->header = NULL;
    }

    return status;
}

/* (Internal) Create header for a new PF (erases any data in the file) */
static pf_status_t create_header(pf_context_t* pf, const char* prefix, const char* file_name) {
    pf_status_t status;
    bool trailing_slash = prefix[strlen(prefix) - 1] == '/';

    status = cb_truncate(pf->handle, PF_HEADER_SIZE);
    if (PF_FAILURE(status))
        goto out;

    status = cb_map(pf->handle, pf->mode, 0, PF_HEADER_SIZE, (void**)&pf->header);
    if (PF_FAILURE(status))
        goto out;

    pf_header_t* hdr = pf->header;
    memset(hdr, 0, PF_HEADER_SIZE);
    hdr->version = PF_FORMAT_VERSION;

    status = cb_crypto_random(hdr->header_iv, PF_IV_SIZE);
    if (PF_FAILURE(status))
        goto out;

    /* TODO: multiple allowed paths support */
    hdr->allowed_paths_size = strlen(file_name)
        + 1 /* slash */
        + strlen(prefix)
        + 1; /* path NULL-terminator */

    /* Trailing slash will be stripped */
    if (trailing_slash)
        hdr->allowed_paths_size--;

    status = PF_STATUS_PATH_TOO_LONG;
    if (hdr->allowed_paths_size > PF_HEADER_ALLOWED_PATHS_SIZE)
        goto out;

    DEBUG_PF("allowed_paths_size: %u\n", hdr->allowed_paths_size);

    /* TODO: multiple allowed paths support */
    if (trailing_slash) {
        snprintf(hdr->allowed_paths, hdr->allowed_paths_size, "%s%s", prefix, file_name);
    } else {
        snprintf(hdr->allowed_paths, hdr->allowed_paths_size, "%s/%s", prefix, file_name);
    }

    status = PF_STATUS_SUCCESS;
out:
    if (PF_FAILURE(status)) {
        if (pf->header) {
            if (PF_FAILURE(cb_unmap(pf->header, PF_HEADER_SIZE))) {
                DEBUG_PF("(failure path) header unmap failed\n");
            }
            pf->header = NULL;
        }
    }

    return status;
}

/* (Internal) Update header MAC for a writable PF and set underlying file size */
static pf_status_t update_header(pf_context_t* pf, size_t data_size) {
    assert(pf && pf->header);
    pf_status_t status;
    pf_header_t* hdr = pf->header;

    DEBUG_PF("pf %p, data size %lu->%lu\n", pf, hdr->data_size, data_size);

    hdr->data_size = data_size;

    /* Regenerate IV */
    status = cb_crypto_random(hdr->header_iv, PF_IV_SIZE);
    if (PF_FAILURE(status))
        goto out;

    /* Calculate header MAC */
    status = cb_crypto_aes_gcm_encrypt(pf->key, PF_WRAP_KEY_SIZE, hdr->header_iv, PF_IV_SIZE,
                                       hdr, PF_HEADER_SIZE - PF_MAC_SIZE,
                                       NULL, 0, /* no data to encrypt */
                                       NULL, /* no output, calc MAC only */
                                       hdr->header_mac, PF_MAC_SIZE);

    if (PF_SUCCESS(status)) {
        DEBUG_PF("data size %lu, iv ", data_size);
        HEXDUMP(hdr->header_iv);
        __DEBUG_PF(", mac ");
        __HEXDUMPNL(hdr->header_mac, PF_MAC_SIZE);

        /* Set the underlying file size */
        size_t size;
        if (data_size > 0)
            size = PF_CHUNK_OFFSET(PF_CHUNK_NUMBER(data_size - 1) + 1);
        else
            size = PF_HEADER_SIZE;

        status = cb_truncate(pf->handle, size);
        if (PF_FAILURE(status))
            goto out;

        DEBUG_PF("underlying file size: %lu\n", size);
    }

out:
    return status;
}

pf_status_t open_common(pf_context_t** pf, pf_handle_t handle, pf_file_mode_t mode,
                        const uint8_t key[PF_WRAP_KEY_SIZE]) {
    *pf = NULL;
    pf_status_t status = check_callbacks();
    if (PF_FAILURE(status))
        goto out;

    status = PF_STATUS_NO_MEMORY;
    *pf = cb_malloc(sizeof(**pf));
    if (!*pf)
        goto out;

    if (cb_debug) {
        (*pf)->debug_buffer = cb_malloc(PF_DEBUG_PRINT_SIZE_MAX);
        if (!(*pf)->debug_buffer)
            goto out;
    }

    (*pf)->plaintext = cb_malloc(PF_CHUNK_SIZE);
    if (!(*pf)->plaintext)
        goto out;

    (*pf)->encrypted = cb_malloc(PF_CHUNK_SIZE);
    if (!(*pf)->encrypted)
        goto out;

    (*pf)->handle = handle;
    (*pf)->mode = mode;
    memcpy(&(*pf)->key, key, PF_WRAP_KEY_SIZE);

    status = PF_STATUS_SUCCESS;

out:
    return status;
}

void free_context(pf_context_t* pf) {
    if (pf) {
        cb_free(pf->plaintext);
        cb_free(pf->encrypted);
        cb_free(pf->debug_buffer);
        cb_free(pf);
    }
}

void open_cleanup(pf_context_t* pf, pf_status_t status, pf_context_t** context) {
    if (PF_FAILURE(status)) {
        free_context(pf);
        *context = NULL;
    } else {
        *context = pf;
    }
}

/* (Public) Open an existing PF */
pf_status_t pf_open(pf_handle_t handle, size_t underlying_size, pf_file_mode_t mode,
                    const uint8_t key[PF_WRAP_KEY_SIZE], pf_context_t** context) {
    pf_context_t* pf   = NULL;
    pf_status_t status = open_common(&pf, handle, mode, key);
    if (PF_FAILURE(status))
        goto out;

    DEBUG_PF("handle %p, context %p, mode %d\n", handle, pf, mode);

    status = map_header(pf, underlying_size);
out:
    open_cleanup(pf, status, context);
    return status;
}

/* (Public) Create a new PF (R+W) */
pf_status_t pf_create(pf_handle_t handle, const char* prefix, const char* file_name,
                      const uint8_t key[PF_WRAP_KEY_SIZE], pf_context_t** context) {
    pf_context_t* pf    = NULL;
    pf_file_mode_t mode = PF_FILE_MODE_READ | PF_FILE_MODE_WRITE;
    pf_status_t status  = open_common(&pf, handle, mode, key);
    if (PF_FAILURE(status))
        goto out;

    DEBUG_PF("handle %p, prefix %s, name %s, context %p\n", handle, prefix, file_name, pf);

    status = create_header(pf, prefix, file_name);
    if (PF_FAILURE(status))
        goto out;

    /* update header for 0 size */
    status = update_header(pf, 0);

out:
    open_cleanup(pf, status, context);
    return status;
}

/* (Public) Close a PF */
pf_status_t pf_close(pf_context_t* pf) {
    assert(pf && pf->header);
    pf_status_t status = check_callbacks();
    if (PF_FAILURE(status))
        goto out;

    DEBUG_PF("pf %p, mode %d\n", pf, pf->mode);

    status = cb_unmap(pf->header, PF_HEADER_SIZE);
    if (PF_FAILURE(status)) {
        DEBUG_PF("failed to unmap header: %d\n", status);
        goto out;
    }

    free_context(pf);
    status = PF_STATUS_SUCCESS;

out:
    return status;
}

/* (Public) Decrypt a single chunk */
pf_status_t pf_decrypt_chunk(pf_context_t* pf, uint64_t chunk_number, const pf_chunk_t* chunk,
                             uint32_t chunk_size, void* output) {
    assert(pf && pf->header);
    pf_status_t status = check_callbacks();
    if (PF_FAILURE(status))
        goto out;

    DEBUG_PF("chunk #%lu: idx 0x%lx, size %u, iv ", chunk_number, chunk->chunk_number, chunk_size);
    HEXDUMP(chunk->chunk_iv);
    __DEBUG_PF(", mac ");
    __HEXDUMPNL(chunk->chunk_mac, PF_MAC_SIZE);

    status = PF_STATUS_BAD_CHUNK;
    /* Verify chunk metadata */
    if (chunk->chunk_number != chunk_number) {
        DEBUG_PF("chunk #%lu: invalid chunk number 0x%lx\n", chunk_number, chunk->chunk_number);
        goto out;
    }

    /* Decrypt data */
    status = cb_crypto_aes_gcm_decrypt(pf->key, PF_WRAP_KEY_SIZE, chunk->chunk_iv, PF_IV_SIZE,
                                       chunk, PF_CHUNK_HEADER_SIZE, /* AAD: chunk header */
                                       chunk->chunk_data, chunk_size, /* input */
                                       (uint8_t*)output, /* output */
                                       chunk->chunk_mac, PF_MAC_SIZE); /* mac */

    if (PF_FAILURE(status)) {
        DEBUG_PF("chunk #%lu: decryption failed: %d\n", chunk_number, status);
        goto out;
    }

    status = PF_STATUS_SUCCESS;
out:
    return status;
}

/* (Public) Read from a PF */
pf_status_t pf_read(pf_context_t* pf, uint64_t offset, size_t size, void* output) {
    pf_chunk_t* chunk  = NULL;
    assert(pf && pf->header);
    pf_status_t status = check_callbacks();
    if (PF_FAILURE(status))
        goto out;

    DEBUG_PF("pf %p, offset %lu, size %lu\n", pf, offset, size);

    status = PF_STATUS_INVALID_PARAMETER;
    if (offset + size > pf->header->data_size) {
        DEBUG_PF("offset + size (%lu) >= file size (%lu)\n", offset + size, pf->header->data_size);
        size = pf->header->data_size - offset;
    }

    if (offset + size <= offset)
        goto out;

    uint64_t first_chunk     = PF_CHUNK_NUMBER(offset);
    uint32_t offset_in_chunk = offset % PF_CHUNK_DATA_MAX;
    uint64_t last_chunk      = PF_CHUNK_NUMBER(offset + size - 1);
    uint64_t output_offset   = 0;
    uint64_t chunk_nr;

    DEBUG_PF("handle %p, chunks: %lu - %lu, 1st offset %u\n",
             pf->handle, first_chunk, last_chunk, offset_in_chunk);

    for (chunk_nr = first_chunk; chunk_nr <= last_chunk; chunk_nr++) {
        status = cb_map(pf->handle, PF_FILE_MODE_READ, PF_CHUNK_OFFSET(chunk_nr), PF_CHUNK_SIZE,
                        (void**)&chunk);

        if (PF_SUCCESS(status)) {
            uint64_t chunk_size = PF_CHUNK_DATA_SIZE(pf->header->data_size, chunk_nr);
            uint32_t read_size = size - output_offset;
            if (read_size > chunk_size - offset_in_chunk)
                read_size = chunk_size - offset_in_chunk;

            status = pf_decrypt_chunk(pf, chunk_nr, chunk, chunk_size, pf->plaintext);
            if (PF_SUCCESS(status)) {
                memcpy((uint8_t*)output + output_offset, (uint8_t*)pf->plaintext + offset_in_chunk, read_size);
                output_offset += read_size;
                offset_in_chunk = 0;
                status = PF_STATUS_SUCCESS;
            }
        }

        if (chunk) {
            if (PF_FAILURE(cb_unmap(chunk, PF_CHUNK_SIZE)))
                DEBUG_PF("chunk unmap failed\n");
        }

        if (PF_FAILURE(status))
            break;
    }

out:
    return status;
}

/* (Public) Encrypt a single chunk */
pf_status_t pf_encrypt_chunk(pf_context_t* pf, uint64_t chunk_number, const void* input,
                             uint32_t chunk_size, pf_chunk_t* output) {
    assert(pf && pf->header);
    pf_status_t status = check_callbacks();
    if (PF_FAILURE(status))
        goto out;

    assert(chunk_size <= PF_CHUNK_DATA_MAX);
    output->chunk_number = chunk_number;

    /* Generate IV for the chunk */
    status = cb_crypto_random(output->chunk_iv, PF_IV_SIZE);
    if (PF_FAILURE(status))
        goto out;

    DEBUG_PF("pf %p, #%lu: size %u, iv ", pf, chunk_number, chunk_size);
    HEXDUMPNL(output->chunk_iv);

    /* Encrypt data */
    status = cb_crypto_aes_gcm_encrypt(pf->key, PF_WRAP_KEY_SIZE, output->chunk_iv, PF_IV_SIZE,
                                       output, PF_CHUNK_HEADER_SIZE, /* AAD: chunk header */
                                       input, chunk_size, /* input */
                                       output->chunk_data, /* output */
                                       output->chunk_mac, PF_MAC_SIZE); /* mac */

    if (status == PF_STATUS_SUCCESS) {
        DEBUG_PF("mac ");
        __HEXDUMPNL(output->chunk_mac, PF_MAC_SIZE);
    }

out:
    return status;
}

static bool is_chunk_uninitialized(const pf_chunk_t* chunk) {
    static const uint8_t zero[PF_IV_SIZE] = {0};
    return memcmp(chunk->chunk_iv, zero, sizeof(zero)) == 0;
}

static pf_status_t write_internal(pf_context_t* pf, uint64_t offset, size_t size, const void* input,
                                  size_t previous_size) {
    pf_status_t status;
    uint64_t first_chunk     = PF_CHUNK_NUMBER(offset);
    uint32_t offset_in_chunk = offset % PF_CHUNK_DATA_MAX;
    uint64_t last_chunk      = PF_CHUNK_NUMBER(offset + size - 1);
    uint64_t input_offset    = 0;
    pf_chunk_t* chunk        = NULL; /* current chunk in the file */

    DEBUG_PF("pf %p, offset %lu, size %lu/%lu, handle %p, chunks: %lu - %lu, 1st offset %u\n",
             pf, offset, size, previous_size, pf->handle, first_chunk, last_chunk, offset_in_chunk);

    for (uint64_t chunk_nr = first_chunk; chunk_nr <= last_chunk; chunk_nr++) {
        /* Read existing chunk (may be uninitialized if the file was extended) */
        status = cb_map(pf->handle, PF_FILE_MODE_READ | PF_FILE_MODE_WRITE,
                        PF_CHUNK_OFFSET(chunk_nr), PF_CHUNK_SIZE, (void**)&chunk);

        if (PF_FAILURE(status))
            goto out;

        uint64_t plaintext_size  = PF_CHUNK_DATA_SIZE(previous_size, chunk_nr);
        uint32_t chunk_data_size = size - input_offset + offset_in_chunk;
        if (chunk_data_size > PF_CHUNK_DATA_MAX)
            chunk_data_size = PF_CHUNK_DATA_MAX;

        /* Size of data being encrypted: might not equal to chunk_data_size
           if the write offset is not at the start of the chunk */
        uint32_t encrypt_size = chunk_data_size;

        /* prepare data to encrypt */
        if (is_chunk_uninitialized(chunk)) {
            /* No existing data in chunk - just encrypt new data,
               make sure to account for writes that skip some bytes (need zeros at the start) */
            if (input) {
                memcpy(pf->plaintext->chunk_data + offset_in_chunk,
                       (uint8_t*)input + input_offset,
                       chunk_data_size - offset_in_chunk);
            } else {
                memset(pf->plaintext->chunk_data + offset_in_chunk,
                       0,
                       chunk_data_size - offset_in_chunk);
            }
        } else {
            /* There is some data in the target chunk - we need to decrypt it,
               overlay new data onto it and then encrypt again. */

            memcpy(pf->plaintext, chunk, PF_CHUNK_HEADER_SIZE);
            status = pf_decrypt_chunk(pf, chunk_nr, chunk, plaintext_size,
                                      pf->plaintext->chunk_data);
            if (PF_FAILURE(status)) {
                DEBUG_PF("pf_decrypt_chunk failed: %d\n", status);
                goto out;
            }

            if (input) {
                /* copy new data */
                memcpy(pf->plaintext->chunk_data + offset_in_chunk,
                       (uint8_t*)input + input_offset,
                       chunk_data_size - offset_in_chunk);
            } else {
                memset(pf->plaintext->chunk_data + offset_in_chunk,
                       0,
                       chunk_data_size - offset_in_chunk);
            }

            if (chunk_data_size < plaintext_size)
                encrypt_size = plaintext_size;
        }

        status = pf_encrypt_chunk(pf, chunk_nr, pf->plaintext->chunk_data, encrypt_size,
                                  pf->encrypted);

        if (PF_FAILURE(status)) {
            DEBUG_PF("pf_encrypt_chunk failed: %d\n", status);
            goto out;
        }

        /* write encrypted chunk to underlying file */
        memcpy(chunk, pf->encrypted, PF_CHUNK_SIZE);

        if (chunk) {
            status = cb_unmap(chunk, PF_CHUNK_SIZE);
            if (PF_FAILURE(status)) {
                DEBUG_PF("failed to unmap chunk\n");
                goto out;
            }
        }
        chunk = NULL;
        input_offset += chunk_data_size - offset_in_chunk;
        offset_in_chunk = 0; /* all remaining chunks are filled from the beginning */
    }

    status = PF_STATUS_SUCCESS;
out:
    return status;
}

/* (Public) Write to a PF (if input is NULL, write zeros) */
pf_status_t pf_write(pf_context_t* pf, uint64_t offset, size_t size, const void* input) {
    assert(pf && pf->header);
    pf_status_t status = check_callbacks();
    if (PF_FAILURE(status))
        goto out;

    status = PF_STATUS_INVALID_CONTEXT;
    if (!pf->header)
        goto out;

    if (!has_mode(pf, PF_FILE_MODE_WRITE))
        return PF_STATUS_INVALID_MODE;

    if (size == 0)
        return PF_STATUS_SUCCESS;

    uint64_t data_size = pf->header->data_size; /* file data size before this write operation */
    DEBUG_PF("pf %p, offset %lu, size %lu, file size %lu\n", pf, offset, size, data_size);

    /* Update file size if the write exceeds current size */
    if (offset + size > data_size) {
        status = update_header(pf, offset + size);
        if (PF_FAILURE(status))
            goto out;

        if (offset - data_size > 0) {
            /* Write zeros to the extended portion of the file */
            status = write_internal(pf, data_size, offset - data_size, NULL, data_size);
            if (PF_FAILURE(status))
                goto out;

            data_size = offset;
        }
    }

    status = write_internal(pf, offset, size, input, data_size);

out:
    return status;
}

/* (Public) Set PF data size */
pf_status_t pf_set_size(pf_context_t* pf, size_t size) {
    pf_chunk_t* chunk  = NULL;
    assert(pf && pf->header);
    pf_status_t status = check_callbacks();
    if (PF_FAILURE(status))
        goto out;

    status = PF_STATUS_INVALID_CONTEXT;
    if (!pf->header)
        goto out;

    status = PF_STATUS_INVALID_MODE;
    if (!has_mode(pf, PF_FILE_MODE_WRITE))
        goto out;

    uint64_t old_size = pf->header->data_size;
    DEBUG_PF("pf %p, size %lu->%lu\n", pf, old_size, size);

    if (size > old_size) /* extend the file with zeros */
        status = pf_write(pf, old_size, size - old_size, NULL);
    else {
        uint64_t old_last_chunk = PF_CHUNKS_COUNT(old_size) - 1;
        uint32_t old_last_chunk_size = PF_CHUNK_DATA_SIZE(old_size, old_last_chunk);
        uint64_t last_chunk = PF_CHUNKS_COUNT(size) - 1;
        uint32_t last_chunk_size = PF_CHUNK_DATA_SIZE(size, last_chunk);

        /* update header and possibly truncate file */
        status = update_header(pf, size);

        /* truncation between chunks -> no chunk update needed */
        if (size > 0 && last_chunk == old_last_chunk) {
            /* update last chunk */
            status = cb_map(pf->handle, PF_FILE_MODE_READ | PF_FILE_MODE_WRITE,
                            PF_CHUNK_OFFSET(last_chunk), PF_CHUNK_SIZE, (void**)&chunk);
            if (PF_FAILURE(status))
                goto out;

            /* decrypt old data */
            status = pf_decrypt_chunk(pf, last_chunk, chunk, old_last_chunk_size, pf->plaintext);
            if (PF_FAILURE(status)) {
                DEBUG_PF("pf_decrypt_chunk failed: %d\n", status);
                goto out;
            }

            /* zero unused part of the chunk (and truncated data) */
            memset(&chunk->chunk_data[last_chunk_size], 0, PF_CHUNK_DATA_MAX - last_chunk_size);

            /* encrypt the data, truncating it */
            status = pf_encrypt_chunk(pf, last_chunk, pf->plaintext, last_chunk_size, chunk);
            if (PF_FAILURE(status)) {
                DEBUG_PF("pf_encrypt_chunk failed: %d\n", status);
                goto out;
            }
        }
    }
out:
    if (chunk) {
        status = cb_unmap(chunk, PF_CHUNK_SIZE);
        if (PF_FAILURE(status)) {
            DEBUG_PF("failed to unmap chunk\n");
            return status;
        }
    }
    return status;
}
