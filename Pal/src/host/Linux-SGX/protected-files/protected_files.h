/* Copyright (C) 2019-2020 Invisible Things Lab
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

/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef PROTECTED_FILES_H_
#define PROTECTED_FILES_H_

#include <stdbool.h>
#include <stdint.h>

/*! Size of the AES-GCM encryption key */
#define PF_KEY_SIZE  16

/*! Size of IV for AES-GCM */
#define PF_IV_SIZE   12

/*! Size of MAC fields */
#define PF_MAC_SIZE  16

typedef uint8_t pf_iv_t[PF_IV_SIZE];
typedef uint8_t pf_mac_t[PF_MAC_SIZE];
typedef uint8_t pf_key_t[PF_KEY_SIZE];
typedef uint8_t pf_keyid_t[32];

typedef enum _pf_status_t {
    PF_STATUS_SUCCESS              = 0,
    PF_STATUS_UNKNOWN_ERROR        = -1,
    PF_STATUS_UNINITIALIZED        = -2,
    PF_STATUS_INVALID_PARAMETER    = -3,
    PF_STATUS_INVALID_MODE         = -4,
    PF_STATUS_NO_MEMORY            = -5,
    PF_STATUS_INVALID_VERSION      = -6,
    PF_STATUS_INVALID_HEADER       = -7,
    PF_STATUS_INVALID_PATH         = -8,
    PF_STATUS_MAC_MISMATCH         = -9,
    PF_STATUS_NOT_IMPLEMENTED      = -10,
    PF_STATUS_CALLBACK_FAILED      = -11,
    PF_STATUS_PATH_TOO_LONG        = -12,
    PF_STATUS_RECOVERY_NEEDED      = -13,
    PF_STATUS_FLUSH_ERROR          = -14,
    PF_STATUS_CRYPTO_ERROR         = -15,
    PF_STATUS_CORRUPTED            = -16,
    PF_STATUS_WRITE_TO_DISK_FAILED = -17,
    PF_STATUS_RECOVERY_IMPOSSIBLE  = -18,
} pf_status_t;

#define PF_SUCCESS(status) ((status) == PF_STATUS_SUCCESS)
#define PF_FAILURE(status) ((status) != PF_STATUS_SUCCESS)

#define PF_NODE_SIZE 4096

/*! PF open modes */
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
 * \brief File read callback
 *
 * \param [in] handle File handle
 * \param [in] buffer Buffer to read to
 * \param [in] offset Offset to read from
 * \param [in] size Number of bytes to read
 * \return PF status
 */
typedef pf_status_t (*pf_read_f)(pf_handle_t handle, void* buffer, size_t offset, size_t size);

/*!
 * \brief File write callback
 *
 * \param [in] handle File handle
 * \param [in] buffer Buffer to write from
 * \param [in] offset Offset to write to
 * \param [in] size Number of bytes to write
 * \return PF status
 */
typedef pf_status_t (*pf_write_f)(pf_handle_t handle, void* buffer, size_t offset, size_t size);

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
 * \brief File open callback
 *
 * \param [in] path File path
 * \param [in] mode Open mode
 * \param [out] handle File handle
 * \param [out] size (optional) File size
 * \return PF status
 */
typedef pf_status_t (*pf_open_f)(const char* path, pf_file_mode_t mode, pf_handle_t* handle,
                                 size_t* size);

/*!
 * \brief File close callback
 *
 * \param [in] handle File handle
 * \return PF status
 */
typedef pf_status_t (*pf_close_f)(pf_handle_t handle);

/*!
 * \brief File delete callback
 *
 * \param [in] path File path
 * \return PF status
 */
typedef pf_status_t (*pf_delete_f)(const char* path);

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
 * \param [in] iv Initialization vector
 * \param [in] aad (optional) Additional authenticated data
 * \param [in] aad_size Size of \a aad in bytes
 * \param [in] input Plaintext data
 * \param [in] input_size Size of \a input in bytes
 * \param [out] output Buffer for encrypted data (size: \a input_size)
 * \param [out] mac MAC computed for \a input and \a aad
 * \return PF status
 */
typedef pf_status_t (*pf_crypto_aes_gcm_encrypt_f)(const pf_key_t* key, const pf_iv_t* iv,
                                                   const void* aad, size_t aad_size,
                                                   const void* input, size_t input_size,
                                                   void* output, pf_mac_t* mac);

/*!
 * \brief AES-GCM decrypt callback
 *
 * \param [in] key AES-GCM key
 * \param [in] iv Initialization vector
 * \param [in] aad (optional) Additional authenticated data
 * \param [in] aad_size Size of \a aad in bytes
 * \param [in] input Encrypted data
 * \param [in] input_size Size of \a input in bytes
 * \param [out] output Buffer for decrypted data (size: \a input_size)
 * \param [in] mac Expected MAC
 * \return PF status
 */
typedef pf_status_t (*pf_crypto_aes_gcm_decrypt_f)(const pf_key_t* key, const pf_iv_t* iv,
                                                   const void* aad, size_t aad_size,
                                                   const void* input, size_t input_size,
                                                   void* output, const pf_mac_t* mac);

/*!
 * \brief Cryptographic random number generator callback
 *
 * \param [out] buffer Buffer to fill with random bytes
 * \param [in] size Size of \a buffer in bytes
 * \return PF status
 */
typedef pf_status_t (*pf_crypto_random_f)(uint8_t* buffer, size_t size);

/*!
 * \brief Initialize I/O callbacks
 *
 * \param [in] malloc_f Allocate memory callback
 * \param [in] free_f Free memory callback
 * \param [in] read_f File read callback
 * \param [in] write_f File write callback
 * \param [in] truncate_f File truncate callback
 * \param [in] flush_f File flush callback
 * \param [in] open_f File open callback
 * \param [in] close_f File close callback
 * \param [in] delete_f File delete callback
 * \param [in] debug_f (optional) Debug print callback
 *
 * \details Must be called before any actual APIs
 */
void pf_set_callbacks(pf_malloc_f malloc_f, pf_free_f free_f, pf_read_f read_f, pf_write_f write_f,
                      pf_truncate_f truncate_f, pf_flush_f flush_f, pf_open_f open_f,
                      pf_close_f close_f, pf_delete_f delete_f, pf_debug_f debug_f);

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

/*! Context representing an open protected file */
typedef struct pf_context* pf_context_t;

/*! Last operation error */
extern pf_status_t pf_last_error;

/* Public API */

/*!
 * \brief Open a protected file
 *
 * \param [in] handle Opened underlying file handle
 * \param [in] path Path to the file. If NULL and \a create is false, don't check path for validity.
 * \param [in] underlying_size Underlying file size
 * \param [in] mode Access mode
 * \param [in] create Overwrite file contents if true
 * \param [in] enable_recovery Enable the recovery file feature
 * \param [in] key Wrap key
 * \param [out] context PF context for later calls
 * \return PF status
 */
pf_status_t pf_open(pf_handle_t handle, const char* path, size_t underlying_size,
                    pf_file_mode_t mode, bool create, bool enable_recovery, const pf_key_t* key,
                    pf_context_t* context);

/*!
 * \brief Close a protected file and commit all changes to disk
 *
 * \param [in] pf PF context
 * \return PF status
 */
pf_status_t pf_close(pf_context_t pf);

/*!
 * \brief Read from a protected file
 *
 * \param [in] pf PF context
 * \param [in] offset Data offset to read from
 * \param [in] size Number of bytes to read
 * \param [out] output Destination buffer
 * \return PF status
 */
pf_status_t pf_read(pf_context_t pf, uint64_t offset, size_t size, void* output);

/*!
 * \brief Write to a protected file
 *
 * \param [in] pf PF context
 * \param [in] offset Data offset to write to
 * \param [in] size Number of bytes to write
 * \param [in] input Source buffer
 * \return PF status
 */
pf_status_t pf_write(pf_context_t pf, uint64_t offset, size_t size, const void* input);

/*!
 * \brief Check whether a PF was opened with specified access mode
 *
 * \param [in] pf PF context
 * \param [in] mode Access mode to check for
 * \param [out] result True if the PF was opened with specified access mode
 * \return PF status
 */
pf_status_t pf_has_mode(pf_context_t pf, pf_file_mode_t mode, bool* result);

/*!
 * \brief Get data size of a PF
 *
 * \param [in] pf PF context
 * \param [out] size Data size of \a pf
 * \return PF status
 */
pf_status_t pf_get_size(pf_context_t pf, size_t* size);

/*!
 * \brief Set data size of a PF
 *
 * \param [in] pf PF context
 * \param [in] size Data size to set
 * \return PF status
 */
pf_status_t pf_set_size(pf_context_t pf, size_t size);

/*!
 * \brief Get underlying handle of a PF
 *
 * \param [in] pf PF context
 * \param [out] handle Handle to the backing file
 * \return PF status
 */
pf_status_t pf_get_handle(pf_context_t pf, pf_handle_t* handle);

#endif
