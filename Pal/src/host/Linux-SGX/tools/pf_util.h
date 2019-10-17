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

#ifndef PF_UTIL_H
#define PF_UTIL_H

#include <stdint.h>
#include "../protected_files.h"

/* High-level protected files helper functions */

/*! Initialize protected files for native environment */
void pf_init();

/*! Generate random PF key and save it to file */
int pf_generate_wrap_key(const char* wrap_key_path);

/*! Convert a single file to the protected format */
int pf_encrypt_file(const char* input_path, const char* output_path, const char* file_name,
                    const char* prefix, uint8_t wrap_key[PF_WRAP_KEY_SIZE]);

/*! Convert a single file from the protected format */
int pf_decrypt_file(const char* input_path, const char* output_path, bool verify_path,
                    uint8_t wrap_key[PF_WRAP_KEY_SIZE]);

/*! Convert a file or directory (recursively) to the protected format */
int pf_encrypt_files(const char* input_dir, const char* output_dir, const char* prefix,
                     const char* wrap_key_path);

/*! Convert a file or directory (recursively) from the protected format */
int pf_decrypt_files(const char* input_dir, const char* output_dir, bool verify_path,
                     const char* wrap_key_path);

/*! AES-GCM encrypt */
pf_status_t openssl_crypto_aes_gcm_encrypt(const uint8_t* key, size_t key_size, const uint8_t* iv,
                                           size_t iv_size, const void* aad, size_t aad_size,
                                           const void* input, size_t input_size, void* output,
                                           uint8_t* mac, size_t mac_size);

/*! AES-GCM decrypt */
pf_status_t openssl_crypto_aes_gcm_decrypt(const uint8_t* key, size_t key_size, const uint8_t* iv,
                                           size_t iv_size, const void* aad, size_t aad_size,
                                           const void* input, size_t input_size, void* output,
                                           const uint8_t* mac, size_t mac_size);

/*! Load PF wrap key from file */
int load_wrap_key(const char* wrap_key_path, uint8_t wrap_key[PF_WRAP_KEY_SIZE]);

#endif
