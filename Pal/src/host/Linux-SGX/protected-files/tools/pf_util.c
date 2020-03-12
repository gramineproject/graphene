/* Copyright (C) 2018-2020 Invisible Things Lab
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

#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/gcm.h>

#include <sys/mman.h>
#include <sys/stat.h>

#include "pf_util.h"
#include "util.h"

/* High-level protected files helper functions. */

/* PF callbacks usable in a standard Linux environment.
   Assume that pf handle is a pointer to file's fd. */

pf_status_t linux_read(pf_handle_t handle, void* buffer, size_t offset, size_t size) {
    int fd = *(int*)handle;
    DBG("linux_read: fd %d, buf %p, offset %zu, size %zu\n", fd, buffer, offset, size);
    if (lseek(fd, offset, SEEK_SET) < 0) {
        ERROR("lseek failed: %s\n", strerror(errno));
        return PF_STATUS_CALLBACK_FAILED;
    }

    off_t offs = 0;
    while (size > 0) {
        ssize_t ret = read(fd, buffer + offs, size);
        if (ret == -EINTR)
            continue;
        if (ret < 0) {
            ERROR("read failed: %s\n", strerror(errno));
            return PF_STATUS_CALLBACK_FAILED;
        }
        size -= ret;
        offs += ret;
    }

    return PF_STATUS_SUCCESS;
}

pf_status_t linux_write(pf_handle_t handle, void* buffer, size_t offset, size_t size) {
    int fd = *(int*)handle;
    DBG("linux_write: fd %d, buf %p, offset %zu, size %zu\n", fd, buffer, offset, size);
    if (lseek(fd, offset, SEEK_SET) < 0) {
        ERROR("lseek failed: %s\n", strerror(errno));
        return PF_STATUS_CALLBACK_FAILED;
    }

    off_t offs = 0;
    while (size > 0) {
        ssize_t ret = write(fd, buffer + offs, size);
        if (ret == -EINTR)
            continue;
        if (ret < 0) {
            ERROR("write failed: %s\n", strerror(errno));
        }
        size -= ret;
        offs += ret;
    }
    return PF_STATUS_SUCCESS;
}

pf_status_t linux_truncate(pf_handle_t handle, size_t size) {
    int fd  = *(int*)handle;
    DBG("linux_truncate: fd %d, size %zu\n", fd, size);
    int ret = ftruncate(fd, size);
    if (ret < 0) {
        ERROR("ftruncate failed: %s\n", strerror(errno));
        return PF_STATUS_CALLBACK_FAILED;
    }

    return PF_STATUS_SUCCESS;
}

pf_status_t linux_flush(pf_handle_t handle) {
    int fd  = *(int*)handle;
    DBG("linux_flush: fd %d\n", fd);
    int ret = fsync(fd);
    if (ret < 0) {
        ERROR("fsync failed: %s\n", strerror(errno));
        return PF_STATUS_CALLBACK_FAILED;
    }

    return PF_STATUS_SUCCESS;
}

/* this callback is only used for creating recovery files and during recovery */
pf_status_t linux_open(const char* path, pf_file_mode_t mode, pf_handle_t* handle, size_t* size) {
    DBG("linux_open: '%s', mode %d\n", path, mode);

    int flags;
    if (mode == PF_FILE_MODE_READ)
        flags = O_RDONLY;
    else if (mode == PF_FILE_MODE_WRITE) /* create recovery file */
        flags = O_WRONLY | O_CREAT | O_TRUNC;
    else /* PF_FILE_MODE_READ|PF_FILE_MODE_WRITE */
        flags = O_RDWR;

    int fd = open(path, flags, 0600);

    if (fd < 0) {
        ERROR("open failed: %s\n", strerror(errno));
        return PF_STATUS_CALLBACK_FAILED;
    }

    if (size) {
        struct stat st;
        if (fstat(fd, &st) < 0) {
            ERROR("fstat failed: %s\n", strerror(errno));
            close(fd);
            return PF_STATUS_CALLBACK_FAILED;
        }

        *size = st.st_size;
    }

    *handle = malloc(sizeof(int));
    if (!*handle) {
        close(fd);
        return PF_STATUS_NO_MEMORY;
    }

    *(int*)*handle = fd;

    return PF_STATUS_SUCCESS;
}

pf_status_t linux_close(pf_handle_t handle) {
    int fd  = *(int*)handle;
    DBG("linux_close: fd %d\n", fd);
    int ret = close(fd);
    if (ret < 0) {
        ERROR("close failed: %s\n", strerror(errno));
        return PF_STATUS_CALLBACK_FAILED;
    }

    free(handle);
    return PF_STATUS_SUCCESS;
}

static pf_status_t linux_delete(const char* path) {
    DBG("linux_delete: '%s'\n", path);
    int ret = unlink(path);
    if (ret < 0) {
        ERROR("unlink failed: %s\n", strerror(errno));
        return PF_STATUS_CALLBACK_FAILED;
    }
    return PF_STATUS_SUCCESS;
}

/* Crypto callbacks for mbedTLS */

pf_status_t mbedtls_aes_gcm_encrypt(const pf_key_t* key, const pf_iv_t* iv,
                                    const void* aad, size_t aad_size,
                                    const void* input, size_t input_size, void* output,
                                    pf_mac_t* mac) {
    pf_status_t status = PF_STATUS_CALLBACK_FAILED;

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, (const unsigned char*)key,
                                 PF_KEY_SIZE * 8);
    if (ret != 0) {
        ERROR("mbedtls_gcm_setkey failed: %d\n", ret);
        goto out;
    }

    ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, input_size, (const unsigned char*)iv,
                                    PF_IV_SIZE, aad, aad_size, input, output, PF_MAC_SIZE,
                                    (unsigned char*)mac);
    if (ret != 0) {
        ERROR("mbedtls_gcm_crypt_and_tag failed: %d\n", ret);
        goto out;
    }

    status = PF_STATUS_SUCCESS;
out:
    mbedtls_gcm_free(&gcm);
    return status;
}

pf_status_t mbedtls_aes_gcm_decrypt(const pf_key_t* key, const pf_iv_t* iv,
                                    const void* aad, size_t aad_size,
                                    const void* input, size_t input_size, void* output,
                                    const pf_mac_t* mac) {
    pf_status_t status = PF_STATUS_CALLBACK_FAILED;

    DBG("mbedtls_aes_gcm_decrypt\n");
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, (const unsigned char*)key,
                                 PF_KEY_SIZE * 8);
    if (ret != 0) {
        ERROR("mbedtls_gcm_setkey failed: %d\n", ret);
        goto out;
    }

    ret = mbedtls_gcm_auth_decrypt(&gcm, input_size, (const unsigned char*)iv, PF_IV_SIZE, aad,
                                   aad_size, (const unsigned char*)mac, PF_MAC_SIZE, input, output);
    if (ret != 0) {
        ERROR("mbedtls_gcm_auth_decrypt failed: %d\n", ret);
        goto out;
    }

    status = PF_STATUS_SUCCESS;
out:
    mbedtls_gcm_free(&gcm);
    return status;
}

static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_prng;
static const char* g_prng_tag = "Graphene protected files library";

pf_status_t mbedtls_random(uint8_t* buffer, size_t size) {
    if (mbedtls_ctr_drbg_random(&g_prng, buffer, size) != 0) {
        ERROR("Failed to get random bytes\n");
        return PF_STATUS_CALLBACK_FAILED;
    }
    return PF_STATUS_SUCCESS;
}

int pf_set_linux_callbacks(pf_debug_f debug_f) {
    /* Initialize mbedTLS CPRNG */
    mbedtls_entropy_init(&g_entropy);
    mbedtls_ctr_drbg_init(&g_prng);
    int ret = mbedtls_ctr_drbg_seed(&g_prng, mbedtls_entropy_func, &g_entropy,
                                    (const unsigned char*)g_prng_tag, strlen(g_prng_tag));

    if (ret != 0) {
        ERROR("Failed to initialize mbedTLS RNG: %d\n", ret);
        return -1;
    }

    pf_set_callbacks(linux_read, linux_write, linux_truncate, linux_flush, linux_open, linux_close,
                     linux_delete, mbedtls_aes_gcm_encrypt, mbedtls_aes_gcm_decrypt, mbedtls_random,
                     debug_f);
    return 0;
}

/* Debug print callback for protected files */
static void cb_debug(const char* msg) {
    DBG("%s", msg);
}

/* Initialize protected files for native environment */
int pf_init() {
    return pf_set_linux_callbacks(cb_debug);
}

/* Generate random PF key and save it to file */
int pf_generate_wrap_key(const char* wrap_key_path) {
    int ret;
    pf_key_t wrap_key;

    ret = mbedtls_ctr_drbg_random(&g_prng, (unsigned char*)&wrap_key, sizeof(wrap_key));
    if (ret != 0) {
        ERROR("Failed to read random bytes: %d\n", ret);
        goto out;
    }

    if (write_file(wrap_key_path, sizeof(wrap_key), wrap_key) != 0) {
        ERROR("Failed to save wrap key\n");
        ret = -1;
        goto out;
    }

    INFO("Wrap key saved to: %s\n", wrap_key_path);
    ret = 0;
out:
    return ret;
}

int load_wrap_key(const char* wrap_key_path, pf_key_t* wrap_key) {
    int ret = -1;
    ssize_t size = 0;
    uint8_t* buf = read_file(wrap_key_path, &size);

    if (!buf) {
        ERROR("Failed to read wrap key\n");
        goto out;
    }

    if (size != PF_KEY_SIZE) {
        ERROR("Wrap key size %zu != %zu\n", size, sizeof(*wrap_key));
        goto out;
    }

    memcpy(wrap_key, buf, sizeof(*wrap_key));
    ret = 0;

out:
    free(buf);
    return ret;
}

/* Convert a single file to the protected format */
int pf_encrypt_file(const char* input_path, const char* output_path, const pf_key_t* wrap_key) {
    int ret            = -1;
    int input          = -1;
    int output         = -1;
    void* input_mem    = MAP_FAILED;
    ssize_t input_size = 0;
    pf_context_t pf    = NULL;
    size_t chunk_size;

    input = open(input_path, O_RDONLY);
    if (input < 0) {
        ERROR("Failed to open input file '%s': %s\n", input_path, strerror(errno));
        goto out;
    }

    output = open(output_path, O_RDWR|O_CREAT, 0664);
    if (output < 0) {
        ERROR("Failed to create output file '%s': %s\n", output_path, strerror(errno));
        goto out;
    }

    INFO("Processing: %s\n", input_path);

    pf_handle_t handle = (pf_handle_t)&output;
    pf_status_t pfs    = pf_open(handle, output_path, /*size=*/0, PF_FILE_MODE_WRITE,
                                 /*create=*/true, /*enable_recovery=*/false, wrap_key, &pf);
    if (PF_FAILURE(pfs)) {
        ERROR("Failed to open output PF: %d\n", pfs);
        goto out;
    }

    /* Process file contents */
    input_size = get_file_size(input);
    if (input_size == -1) {
        ERROR("Failed to stat input file '%s': %s\n", input_path, strerror(errno));
        goto out;
    }

    ssize_t input_offset = 0;

    if (input_size > 0) {
        input_mem = mmap(NULL, input_size, PROT_READ, MAP_PRIVATE, input, 0);
        if (input_mem == MAP_FAILED) {
            ERROR("Failed to mmap input file '%s': %s\n", input_path, strerror(errno));
            goto out;
        }

        while (input_offset < input_size) {
            chunk_size = input_size - input_offset;
            if (chunk_size > PF_NODE_SIZE)
                chunk_size = PF_NODE_SIZE;
            pfs = pf_write(pf, input_offset, chunk_size, (uint8_t*)input_mem + input_offset);
            if (PF_FAILURE(pfs)) {
                ERROR("Failed to write to output PF: %d\n", pfs);
                goto out;
            }

            input_offset += chunk_size;
        }
    }

    ret = 0;

out:
    if (pf) {
        if (PF_FAILURE(pf_close(pf))) {
            ERROR("failed to close PF\n");
            ret = -1;
        }
    }

    if (input >= 0)
        close(input);
    if (output >= 0)
        close(output);
    if (input_mem != MAP_FAILED)
        munmap(input_mem, input_size);
    return ret;
}

/* Convert a single file from the protected format */
int pf_decrypt_file(const char* input_path, const char* output_path, bool verify_path,
                    const pf_key_t* wrap_key) {
    int ret          = -1;
    int input        = -1;
    int output       = -1;
    void* output_mem = MAP_FAILED;
    pf_context_t pf  = NULL;

    input = open(input_path, O_RDONLY);
    if (input < 0) {
        ERROR("Failed to open input file '%s': %s\n", input_path, strerror(errno));
        goto out;
    }

    output = open(output_path, O_RDWR|O_CREAT, 0664);
    if (output < 0) {
        ERROR("Failed to create output file '%s': %s\n", output_path, strerror(errno));
        goto out;
    }

    INFO("Processing: %s\n", input_path);

    /* Get input file size */
    struct stat st;
    if (fstat(input, &st) < 0) {
        ERROR("Failed to stat input file '%s': %s\n", input_path, strerror(errno));
        goto out;
    }

    const char* path = verify_path ? input_path : NULL;
    pf_status_t pfs = pf_open((pf_handle_t)&input, path, st.st_size, PF_FILE_MODE_READ,
                              /*create=*/false, /*enable_recovery=*/false, wrap_key, &pf);
    if (PF_FAILURE(pfs)) {
        ERROR("Opening protected input file failed: %d\n", pfs);
        goto out;
    }

    /* Process file contents */
    size_t input_size;
    size_t input_offset = 0;
    size_t chunk_size   = PF_NODE_SIZE;

    pfs = pf_get_size(pf, &input_size);
    if (PF_FAILURE(pfs)) {
        ERROR("pf_get_size failed: %d\n", pfs);
        goto out;
    }

    if (input_size > SSIZE_MAX) {
        ERROR("Input file size too large\n");
        goto out;
    }

    if (ftruncate(output, input_size) < 0) {
        ERROR("ftruncate output file '%s' failed: %s\n", output_path, strerror(errno));
        goto out;
    }

    if (input_size > 0) {
        output_mem = mmap(NULL, input_size, PROT_WRITE, MAP_SHARED, output, 0);
        if (output_mem == MAP_FAILED) {
            ERROR("Failed to mmap output file '%s': %s\n", output_path, strerror(errno));
            goto out;
        }

        while (input_offset < input_size) {
            chunk_size = input_size - input_offset;
            if (chunk_size > PF_NODE_SIZE)
                chunk_size = PF_NODE_SIZE;

            pfs = pf_read(pf, input_offset, chunk_size, output_mem + input_offset);
            if (PF_FAILURE(pfs)) {
                ERROR("Read from protected file failed (offset %" PRIu64 ", size %" PRIu64 "): %d\n",
                      input_offset, chunk_size, pfs);
                goto out;
            }

            input_offset += chunk_size;
        }
    }

    ret = 0;

out:
    if (pf)
        pf_close(pf);
    if (input >= 0)
        close(input);
    if (output >= 0)
        close(output);
    if (output_mem != MAP_FAILED)
        munmap(output_mem, input_size);
    return ret;
}

enum processing_mode_t {
    MODE_ENCRYPT = 1,
    MODE_DECRYPT = 2,
};

static int process_files(const char* input_dir, const char* output_dir, const char* wrap_key_path,
                         enum processing_mode_t mode, bool verify_path) {
    int ret = -1;
    pf_key_t wrap_key;
    struct stat st;
    char* input_path  = NULL;
    char* output_path = NULL;

    if (mode != MODE_ENCRYPT && mode != MODE_DECRYPT) {
        ERROR("Invalid mode: %d\n", mode);
        goto out;
    }

    ret = load_wrap_key(wrap_key_path, &wrap_key);
    if (ret != 0)
        goto out;

    if (stat(input_dir, &st) != 0) {
        ERROR("Failed to stat input path %s: %s\n", input_dir, strerror(errno));
        goto out;
    }

    /* single file? */
    if (S_ISREG(st.st_mode)) {
        if (mode == MODE_ENCRYPT)
            return pf_encrypt_file(input_dir, output_dir, &wrap_key);
        else
            return pf_decrypt_file(input_dir, output_dir, verify_path, &wrap_key);
    }

    ret = mkdir(output_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    if (ret != 0 && errno != EEXIST) {
        ERROR("Failed to create directory %s: %s\n", output_dir, strerror(errno));
        goto out;
    }

    /* Process input directory */
    struct dirent* dir;
    DIR* dfd = opendir(input_dir);
    if (!dfd) {
        ERROR("Failed to open input directory: %s\n", strerror(errno));
        goto out;
    }

    size_t input_path_size, output_path_size;
    while ((dir = readdir(dfd)) != NULL) {
        if (!strcmp(dir->d_name, "."))
            continue;
        if (!strcmp(dir->d_name, ".."))
            continue;

        input_path_size = strlen(input_dir) + 1 + strlen(dir->d_name) + 1;
        output_path_size = strlen(output_dir) + 1 + strlen(dir->d_name) + 1;

        input_path = malloc(input_path_size);
        if (!input_path) {
            ERROR("No memory\n");
            goto out;
        }

        output_path = malloc(output_path_size);
        if (!output_path) {
            ERROR("No memory\n");
            goto out;
        }

        snprintf(input_path, input_path_size, "%s/%s", input_dir, dir->d_name);
        snprintf(output_path, output_path_size, "%s/%s", output_dir, dir->d_name);

        if (stat(input_path, &st) != 0) {
            ERROR("Failed to stat input file %s: %s\n", input_path, strerror(errno));
            goto out;
        }

        if (S_ISREG(st.st_mode)) {
            if (mode == MODE_ENCRYPT)
                ret = pf_encrypt_file(input_path, output_path, &wrap_key);
            else
                ret = pf_decrypt_file(input_path, output_path, verify_path, &wrap_key);

            if (ret != 0)
                goto out;
        } else if (S_ISDIR(st.st_mode)) {
            /* process directory recursively */
            ret = process_files(input_path, output_path, wrap_key_path, mode, verify_path);
            if (ret != 0)
                goto out;
        } else {
            INFO("Skipping non-regular file %s\n", input_path);
        }

        free(input_path);
        input_path = NULL;
        free(output_path);
        output_path = NULL;
    }
    ret = 0;

out:
    free(input_path);
    free(output_path);
    return ret;
}

/* Convert a file or directory (recursively) to the protected format */
int pf_encrypt_files(const char* input_dir, const char* output_dir, const char* wrap_key_path) {
    return process_files(input_dir, output_dir, wrap_key_path, MODE_ENCRYPT, false);
}

/* Convert a file or directory (recursively) from the protected format */
int pf_decrypt_files(const char* input_dir, const char* output_dir, bool verify_path,
                     const char* wrap_key_path) {
    return process_files(input_dir, output_dir, wrap_key_path, MODE_DECRYPT, verify_path);
}
