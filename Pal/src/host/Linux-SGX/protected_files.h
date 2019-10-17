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

#ifndef PROTECTED_FILES_H
#define PROTECTED_FILES_H

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
Protected file (PF) format requirements:
- Confidentiality (encryption). A party without the wrap key should not be able to
  read data contained within.
- Integrity (tamper detection). Unauthorized PF modifications should be detected and such
  file should not be usable.
- Path/file swap protection. A PF should only be accessible when located in a path(s)
  explicitely defined in the PF metadata.
- Ease of use for transparent I/O operations in Graphene. Graphene payload doesn't need to
  know anything about internal PF implementation (or that an accessed file is a PF at all).
- (Possibly in the future) Streamed data support.

PF consist of a header with some global metadata followed by zero or more data chunks.
Each chunk is encrypted separately to reduce performance impact of crypto operations.

AES-GCM is used for authenticated encryption and decryption.

Implementation is designed to be pretty modular and as environment-independent as possible
since it's used by the Graphene enclave and by non-Graphene (native) tools.

TODO:
- Secure provisioning of the wrap key.
- Currently only one allowed path is supported. Multiple allowed paths will allow for
  (sym)link support in the future.
- Thorough cryptographic review is needed. One known weakness is a chunk swap attack:
  same-numbered chunks can be swapped between files without detection. This will be
  fixed in the next iteration.
- Possible performance optimizations (in the PF implementation and Graphene handlers).
- Tests with invalid/corrupted/tampered contents of PFs (not ported from the original
  implementation yet).
- Convert into a library if needed.
*/

/*! File format version */
#define PF_FORMAT_VERSION 4

/*! Size of the AES-GCM encryption key */
#define PF_WRAP_KEY_SIZE  16

/*! Size of IV for AES-GCM */
#define PF_IV_SIZE        12

/*! Size of MAC fields */
#define PF_MAC_SIZE       16

/*! Total size of a chunk */
#define PF_CHUNK_SIZE     (4 * 0x1000)

/*! File offset for the first chunk, page aligned for easy mmap-ing */
#define PF_CHUNKS_OFFSET             0x1000

/*! Header size (constant) */
#define PF_HEADER_SIZE               PF_CHUNKS_OFFSET

/*! Maximum size for allowed paths */
#define PF_HEADER_ALLOWED_PATHS_SIZE (PF_HEADER_SIZE -4 -8 -PF_IV_SIZE -4 -PF_MAC_SIZE)

/*! Maximum number of data bytes in a chunk */
#define PF_CHUNK_DATA_MAX (PF_CHUNK_SIZE -8 -PF_IV_SIZE -12 -PF_MAC_SIZE)

/*! Protected file header */
typedef struct __attribute__((packed)) _pf_header_t {
    uint32_t version; //!< File format version
    uint64_t data_size; //!< Original file size
    uint8_t  header_iv[PF_IV_SIZE]; //!< AES-GCM IV
    uint32_t allowed_paths_size; //!< Size of allowed paths that follow (including NULL terminators)
    char     allowed_paths[PF_HEADER_ALLOWED_PATHS_SIZE]; //!< C-string paths, padded with zeros
    uint8_t  header_mac[PF_MAC_SIZE]; //!< AES-GCM tag of header up to this field
} pf_header_t;

static_assert(sizeof(pf_header_t) == PF_HEADER_SIZE, "incorrect struct size");

/*! Protected file chunk, each is individually encrypted */
typedef struct __attribute__((packed)) _pf_chunk_t {
    uint64_t chunk_number; //!< Sequential in a file, starting from 0
    uint8_t  chunk_iv[PF_IV_SIZE]; //!< AES-GCM IV
    uint8_t  padding[12]; //!< Unused
    uint8_t  chunk_data[PF_CHUNK_DATA_MAX]; //!< Use PF_CHUNK_DATA_SIZE for actual data size
    uint8_t  chunk_mac[PF_MAC_SIZE]; //!< AES-GCM tag for chunk_data, fields before are used as aad
} pf_chunk_t;

static_assert(sizeof(pf_chunk_t) == PF_CHUNK_SIZE, "incorrect struct size");

/*! Size of chunk metadata/header */
#define PF_CHUNK_HEADER_SIZE      (offsetof(pf_chunk_t, chunk_data))
/*! Number of a chunk containing given data offset */
#define PF_CHUNK_NUMBER(offset)   ((offset) / PF_CHUNK_DATA_MAX)
/*! Number of chunks needed for the given data size */
#define PF_CHUNKS_COUNT(size)     ((size) > 0 ? PF_CHUNK_NUMBER((size) - 1) + 1 : 0)
/*! Offset of a given chunk relative to the start of the file */
#define PF_CHUNK_OFFSET(chunk_nr) (PF_CHUNKS_OFFSET + (chunk_nr) * PF_CHUNK_SIZE)
/*! Size of chunk data */
#define PF_CHUNK_DATA_SIZE(size, chunk_nr) (((chunk_nr) < (PF_CHUNKS_COUNT(size) - 1)) ? PF_CHUNK_DATA_MAX : (size % PF_CHUNK_DATA_MAX))

/*! Return values for PF functions */
typedef enum _pf_status_t {
    PF_STATUS_SUCCESS           = 0,
    PF_STATUS_UNKNOWN_ERROR     = -1,
    PF_STATUS_UNINITIALIZED     = -2,
    PF_STATUS_INVALID_PARAMETER = -3,
    PF_STATUS_INVALID_MODE      = -4,
    PF_STATUS_INVALID_CONTEXT   = -5,
    PF_STATUS_NO_MEMORY         = -6,
    PF_STATUS_BAD_VERSION       = -7,
    PF_STATUS_BAD_HEADER        = -8,
    PF_STATUS_BAD_CHUNK         = -9,
    PF_STATUS_MAC_MISMATCH      = -10,
    PF_STATUS_NOT_IMPLEMENTED   = -11,
    PF_STATUS_CALLBACK_FAILED   = -12,
    PF_STATUS_PATH_TOO_LONG     = -13,
} pf_status_t;

#define PF_SUCCESS(status) ((status) == PF_STATUS_SUCCESS)
#define PF_FAILURE(status) ((status) != PF_STATUS_SUCCESS)

/*! PF open/map modes */
typedef enum _pf_file_mode_t {
    PF_FILE_MODE_READ  = 1,
    PF_FILE_MODE_WRITE = 2,
} pf_file_mode_t;

/*! Opaque file handle type, interpreted by callbacks as necessary */
typedef void* pf_handle_t;

/*!
 * \brief Allocate memory callback
 *
 * \param [in] size Size to allocate
 * \return Allocated address or NULL if failed
 *
 * \details Must zero the allocated buffer
 */
typedef void* (*pf_malloc_f)(size_t size);

/*!
 * \brief Free memory callback
 *
 * \param [in] address Address to free
 *
 * \details Must accept NULL pointers
 */
typedef void (*pf_free_f)(void* address);

/*!
 * \brief File map callback
 *
 * \param [in] handle File handle
 * \param [in] mode Access mode
 * \param [in] offset Starting offset of the region to map
 * \param [in] size Size of the region to map
 * \param [out] address Mapped address
 * \return PF status
 */
typedef pf_status_t (*pf_map_f)(pf_handle_t handle, pf_file_mode_t mode, size_t offset, size_t size,
                                void** address);

/*!
 * \brief File unmap callback
 *
 * \param [in] address Address to unmap
 * \param [in] size Size of mapped region
 * \return PF status
 */
typedef pf_status_t (*pf_unmap_f)(void* address, size_t size);

/*!
 * \brief File truncate callback
 *
 * \param [in] handle File handle
 * \param [in] size Target file size
 * \return PF status
 */
typedef pf_status_t (*pf_truncate_f)(pf_handle_t handle, size_t size);

/*!
 * \brief File flush callback
 *
 * \param [in] handle File handle
 * \return PF status
 */
typedef pf_status_t (*pf_flush_f)(pf_handle_t handle);

/*!
 * \brief Debug print callback
 *
 * \param [in] msg Message to print
 */
typedef void (*pf_debug_f)(const char* msg);

/*!
 * \brief AES-GCM encrypt callback
 *
 * \param [in] key AES-GCM key
 * \param [in] key_size Size of \a key in bytes
 * \param [in] iv Initialization vector
 * \param [in] iv_size Size of \a iv in bytes
 * \param [in] aad (optional) Additional authenticated data
 * \param [in] aad_size Size of \a aad in bytes
 * \param [in] input Plaintext data
 * \param [in] input_size Size of \a input in bytes
 * \param [out] output Buffer for encrypted data (size: \a input_size)
 * \param [out] mac MAC computed for \a input and \a aad
 * \param [in] mac_size Size of \a mac in bytes
 * \return PF status
 */
typedef pf_status_t (*pf_crypto_aes_gcm_encrypt_f)(const uint8_t* key, size_t key_size,
                                                   const uint8_t* iv, size_t iv_size,
                                                   const void* aad, size_t aad_size,
                                                   const void* input, size_t input_size,
                                                   void* output, uint8_t* mac, size_t mac_size);

/*!
 * \brief AES-GCM decrypt callback
 *
 * \param [in] key AES-GCM key
 * \param [in] key_size Size of \a key in bytes
 * \param [in] iv Initialization vector
 * \param [in] iv_size Size of \a iv in bytes
 * \param [in] aad (optional) Additional authenticated data
 * \param [in] aad_size Size of \a aad in bytes
 * \param [in] input Encrypted data
 * \param [in] input_size Size of \a input in bytes
 * \param [out] output Buffer for decrypted data (size: \a input_size)
 * \param [in] mac Expected MAC
 * \param [in] mac_size Size of \a mac in bytes
 * \return PF status
 */
typedef pf_status_t (*pf_crypto_aes_gcm_decrypt_f)(const uint8_t* key, size_t key_size,
                                                   const uint8_t* iv, size_t iv_size,
                                                   const void* aad, size_t aad_size,
                                                   const void* input, size_t input_size,
                                                   void* output, const uint8_t* mac,
                                                   size_t mac_size);

/*!
 * \brief Cryptographic random number generator callback
 *
 * \param [out] buffer Buffer to fill with random bytes
 * \param [in] size Size of \a buffer in bytes
 * \return PF status
 */
typedef pf_status_t (*pf_crypto_random_f)(uint8_t* buffer, size_t size);

#define PF_DEBUG_PRINT_SIZE_MAX 4096

/*! Context holding information for an opened protected file */
typedef struct _pf_context_t {
    pf_handle_t    handle; //!< Underlying file handle
    pf_header_t*   header; //!< PF header mapped in memory
    pf_file_mode_t mode; //!< Access mode
    uint8_t        key[PF_WRAP_KEY_SIZE]; //!< Wrap key
    char*          debug_buffer; //!< Buffer for debug output
    pf_chunk_t*    plaintext; //!< Temporary chunk buffer
    pf_chunk_t*    encrypted; //!< Temporary chunk buffer
} pf_context_t;

/*!
 * \brief Initialize I/O callbacks
 *
 * \param [in] malloc_f Allocate memory callback
 * \param [in] free_f Free memory callback
 * \param [in] map_f File map callback
 * \param [in] unmap_f File unmap callback
 * \param [in] truncate_f File truncate callback
 * \param [in] flush_f File flush callback
 * \param [in] debug_f (optional) Debug print callback
 *
 * \details Must be called before any actual APIs
 */
void pf_set_callbacks(pf_malloc_f malloc_f, pf_free_f free_f, pf_map_f map_f, pf_unmap_f unmap_f,
                      pf_truncate_f truncate_f, pf_flush_f flush_f, pf_debug_f debug_f);

/*!
 * \brief Initialize cryptographic callbacks
 *
 * \param [in] crypto_aes_gcm_encrypt_f AES-GCM encrypt callback
 * \param [in] crypto_aes_gcm_decrypt_f AES-GCM decrypt callback
 * \param [in] crypto_random_f Cryptographic random number generator callback
 *
 * \details Must be called before any actual APIs
 */
void pf_set_crypto_callbacks(pf_crypto_aes_gcm_encrypt_f crypto_aes_gcm_encrypt_f,
                             pf_crypto_aes_gcm_decrypt_f crypto_aes_gcm_decrypt_f,
                             pf_crypto_random_f crypto_random_f);

/*!
 * \brief Open an existing protected file
 *
 * \param [in] handle Opened underlying file handle
 * \param [in] underlying_size Underlying file size
 * \param [in] mode Access mode
 * \param [in] key Wrap key
 * \param [out] context PF context for later calls
 * \return PF status
 */
pf_status_t pf_open(pf_handle_t handle, size_t underlying_size, pf_file_mode_t mode,
                    const uint8_t key[PF_WRAP_KEY_SIZE], pf_context_t** context);

/*!
 * \brief Create a new protected file
 *
 * \param [in] handle Opened underlying file handle
 * \param [in] prefix Path prefix for allowed file name
 * \param [in] file_name Allowed file name
 * \param [in] key Wrap key
 * \param [out] context PF context for later calls
 * \return PF status
 */
pf_status_t pf_create(pf_handle_t handle, const char* prefix, const char* file_name,
                      const uint8_t key[PF_WRAP_KEY_SIZE], pf_context_t** context);

/*!
 * \brief Close a protected file
 *
 * \param [in] pf PF context
 * \return PF status
 *
 * \details Any writable mmap buffers are written to the PF by this function
 */
pf_status_t pf_close(pf_context_t* pf);

/*!
 * \brief Read from a protected file
 *
 * \param [in] pf PF context
 * \param [in] offset Data offset to read from
 * \param [in] size Number of bytes to read
 * \param [out] output Destination buffer
 * \return PF status
 */
pf_status_t pf_read(pf_context_t* pf, uint64_t offset, size_t size, void* output);

/*!
 * \brief Write to a protected file
 *
 * \param [in] pf PF context
 * \param [in] offset Data offset to write to
 * \param [in] size Number of bytes to write
 * \param [in] input Source buffer
 * \return PF status
 */
pf_status_t pf_write(pf_context_t* pf, uint64_t offset, size_t size, const void* input);

/*!
 * \brief Decrypt a single chunk
 *
 * \param [in] pf PF context
 * \param [in] chunk_number Expected chunk number
 * \param [in] chunk Encrypted chunk with metadata (pf_chunk_t)
 * \param [in] chunk_size Size of \a output
 * \param [out] output Decrypted chunk data
 * \return PF status
 */
pf_status_t pf_decrypt_chunk(pf_context_t* pf, uint64_t chunk_number, const pf_chunk_t* chunk,
                             uint32_t chunk_size, void* output);

/*!
 * \brief Encrypt a single chunk
 *
 * \param [in] pf PF context
 * \param [in] chunk_number Chunk number
 * \param [in] input Chunk data to encrypt
 * \param [in] chunk_size Size of \a input
 * \param [out] output Output encrypted chunk, size PF_CHUNK_SIZE
 * \return PF status
 */
pf_status_t pf_encrypt_chunk(pf_context_t* pf, uint64_t chunk_number, const void* input,
                             uint32_t chunk_size, pf_chunk_t* output);

/*!
 * \brief Check whether a PF was opened with specified access mode
 *
 * \param [in] pf PF context
 * \param [in] mode Access mode to check for
 * \param [out] result True if the PF was opened with specified access mode
 * \return PF status
 */
pf_status_t pf_has_mode(pf_context_t* pf, pf_file_mode_t mode, bool* result);

/*!
 * \brief Check whether the specified path is in allowed paths for a PF
 *
 * \param [in] pf PF context
 * \param [in] path Path to check
 * \param [out] result True if \a path is in allowed paths for this PF
 * \return PF status
 */
pf_status_t pf_check_path(pf_context_t* pf, const char* path, bool* result);

/*!
 * \brief Get data size of a PF
 *
 * \param [in] pf PF context
 * \param [out] size Data size of \a pf
 * \return PF status
 */
pf_status_t pf_get_size(pf_context_t* pf, uint64_t* size);

/*!
 * \brief Set data size of a PF
 *
 * \param [in] pf PF context
 * \param [in] size Data size to set
 * \return PF status
 */
pf_status_t pf_set_size(pf_context_t* pf, size_t size);

#endif /* PROTECTED_FILES_H */
