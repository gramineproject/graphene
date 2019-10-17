/* Copyright (C) 2019 Invisible Things Lab
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

#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

#include "pf_util.h"
#include "util.h"

/* Tamper with a PF in various ways for testing purposes.
   Wrap key is needed, some modifications change the key and/or (meta)data
   to create invalid MACs etc. */

/* Command line options */
struct option g_options[] = {
    { "input", required_argument, 0, 'i' },
    { "output", required_argument, 0, 'o' },
    { "wrap-key", required_argument, 0, 'w' },
    { "verbose", no_argument, 0, 'v' },
    { "help", no_argument, 0, 'h' },
    { 0, 0, 0, 0 }
};

void usage() {
    INFO("\nUsage: pf_tamper [options]\n");
    INFO("To enable all modifications, the PF should contain at least 3 chunks\n");
    INFO("and the last one should not be full.\n");
    INFO("\nAvailable options:\n");
    INFO("  --help, -h           Display this help\n");
    INFO("  --verbose, -v        Enable verbose output\n");
    INFO("  --wrap-key, -w PATH  Path to wrap key file\n");
    INFO("  --input, -i PATH     Source file to be tampered with (must be a valid PF)\n");
    INFO("  --output, -o PATH    Directory where modified files will be written to\n");
}

int truncate_pf(const char* input_name, size_t input_size, const void* input,
                const char* output_dir, char* output_path, size_t output_path_size,
                const char* suffix, const char* msg, bool extend, size_t size) {

    int ret;
    if (extend || input_size > size) {
        snprintf(output_path, output_path_size, "%s/%s.%s", output_dir, input_name, suffix);
        INFO("[*] %s: %s\n", msg, output_path);
        if (input_size >= size) {
            ret = write_file(output_path, size, input);
        } else {
            ret = write_file(output_path, input_size, input);
            if (ret < 0)
                return ret;
            ret = truncate(output_path, size);
        }
        if (ret < 0)
            return ret;
    }
    return 0;
}

#define TRUNCATE(suffix, msg, extend, size) \
{ \
    ret = truncate_pf(input_name, input_size, input, output_dir, output_path, output_path_size, \
                      suffix, msg, extend, size); \
    if (ret < 0) \
        goto out; \
}

#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))

int tamper_truncate(const char* input_name, size_t input_size, const void* input,
                    const char* output_dir, char* output_path, size_t output_path_size) {
    int ret = -1;

    snprintf(output_path, output_path_size, "%s/%s.trunc_zero", output_dir, input_name);
    INFO("[*] Zero-size file: %s\n", output_path);
    ret = write_file(output_path, 0, input);
    if (ret < 0)
        goto out;

    TRUNCATE("trunc_header", "Truncated header", false, PF_HEADER_SIZE / 2);

    TRUNCATE("trunc_chunk_metadata", "Truncated chunk (metadata)", false,
        PF_CHUNKS_OFFSET + offsetof(pf_chunk_t, chunk_iv) + FIELD_SIZEOF(pf_chunk_t, chunk_iv) / 2);

    TRUNCATE("trunc_chunk_data", "Truncated chunk (data)", false,
        PF_CHUNKS_OFFSET + offsetof(pf_chunk_t, chunk_data) + 10);

    TRUNCATE("trunc_chunks", "Truncated between chunks", false, PF_CHUNK_OFFSET(1));

    TRUNCATE("trunc_extend_1", "Extended (+1)", true, input_size + 1);

    TRUNCATE("trunc_extend_2", "Extended (+chunk)", true, input_size + PF_CHUNK_SIZE);

    ret = 0;
out:
    return ret;
}

void* open_output(const char* path, size_t size, const void* input) {
    void* mem = MAP_FAILED;
    int fd = open(path, O_RDWR|O_CREAT, 0664);
    if (fd < 0) {
        ERROR("Failed to open output file '%s': %s\n", path, strerror(errno));
        goto out;
    }

    if (ftruncate(fd, size) < 0) {
        ERROR("Failed to ftruncate output file '%s': %s\n", path, strerror(errno));
        goto out;
    }

    mem = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (mem == MAP_FAILED) {
        ERROR("Failed to mmap output file '%s': %s\n", path, strerror(errno));
        goto out;
    }

    memcpy(mem, input, size);

out:
    if (fd >= 0)
        close(fd);
    return mem;
}

/* copy input PF and apply some modifications */
#define __BREAK_PF(file_suffix, msg, ...) \
{ \
    snprintf(output_path, output_path_size, "%s/%s." file_suffix, output_dir, input_name); \
    INFO("[*] " msg ": %s\n", output_path); \
    output = open_output(output_path, size, input); \
    if (output == MAP_FAILED) \
        goto out; \
    __VA_ARGS__ \
    munmap(output, size); \
}

/* if fix is true, also create a file with correct header's MAC */
#define BREAK_HEADER(file_suffix, msg, fix, ...) \
{ \
    __BREAK_PF(file_suffix, "Header " msg, __VA_ARGS__); \
    if (fix) { \
        __BREAK_PF(file_suffix "_fixed", "Header (fixed) " msg, __VA_ARGS__ { \
            openssl_crypto_aes_gcm_encrypt(key, PF_WRAP_KEY_SIZE, output->header_iv, PF_IV_SIZE, \
                                           output, PF_HEADER_SIZE-PF_MAC_SIZE, NULL, 0, NULL, \
                                           output->header_mac, PF_MAC_SIZE); \
        }); \
    } \
}

int tamper_header(const char* input_name, size_t size, const void* input, const uint8_t* key,
                  const char* output_dir, char* output_path, size_t output_path_size) {
    int ret = -1;
    pf_header_t* output = MAP_FAILED;

    BREAK_HEADER("header_version_1", "invalid version (0)", true,
        {output->version = 0;});

    BREAK_HEADER("header_version_2", "invalid version (max)", true,
        {output->version = UINT32_MAX;});

    BREAK_HEADER("header_size_1", "invalid size (0)", false,
        {output->data_size = 0;});

    BREAK_HEADER("header_size_2", "invalid size (x-1)", true,
        {output->data_size--;});

    BREAK_HEADER("header_size_3", "invalid size (x+1)", true,
        {output->data_size++;});

    BREAK_HEADER("header_size_4", "invalid size (max)", true,
        {output->data_size = UINT64_MAX;});

    BREAK_HEADER("header_iv", "invalid IV", false,
        {output->header_iv[0] ^= 1;});

    BREAK_HEADER("header_aps_1", "invalid allowed_paths_size (0)", true,
        {output->allowed_paths_size = 0;});

    BREAK_HEADER("header_mac", "invalid MAC", false,
        {output->header_mac[PF_MAC_SIZE-1] ^= 1;});

    /* These may not be strictly invalid, but they should result in inaccessible PFs */
    BREAK_HEADER("header_aps_2", "invalid allowed_paths_size (x-1)", true,
        {output->allowed_paths_size--;});

    BREAK_HEADER("header_aps_3", "invalid allowed_paths_size (x+1)", true,
        {output->allowed_paths_size++;});

    BREAK_HEADER("header_aps_4", "invalid allowed_paths_size (max)", true,
        {output->allowed_paths_size = UINT32_MAX;});

    BREAK_HEADER("header_ap_1", "invalid allowed_paths", true,
        {output->allowed_paths[0]++;});

    ret = 0;
out:
    return ret;
}

/* if fix is true, also create a file with correct chunk's MAC/encrypted data */
#define BREAK_CHUNK(file_suffix, msg, fix, ...) \
{ \
    __BREAK_PF(file_suffix, "Chunk " msg, __VA_ARGS__); \
    if (fix) { \
        uint8_t decrypted[PF_CHUNK_SIZE]; \
        __BREAK_PF(file_suffix "_fixed", "Chunk (fixed) " msg, { \
            openssl_crypto_aes_gcm_decrypt(key, PF_WRAP_KEY_SIZE, chunk->chunk_iv, PF_IV_SIZE, \
                                           chunk, PF_CHUNK_HEADER_SIZE, \
                                           chunk->chunk_data, chunk_size, decrypted, \
                                           chunk->chunk_mac, PF_MAC_SIZE); \
        } \
        __VA_ARGS__ \
        { \
            openssl_crypto_aes_gcm_encrypt(key, PF_WRAP_KEY_SIZE, chunk->chunk_iv, PF_IV_SIZE, \
                                           chunk, PF_CHUNK_HEADER_SIZE, \
                                           decrypted, chunk_size, chunk->chunk_data, \
                                           chunk->chunk_mac, PF_MAC_SIZE); \
        }); \
    } \
}

int tamper_chunk(const char* input_name, size_t size, const void* input, const uint8_t* key,
                 const char* output_dir, char* output_path, size_t output_path_size) {
    int ret = -1;
    void* output = MAP_FAILED;
    pf_chunk_t* chunk;
    pf_header_t* header = (pf_header_t*)input;
    uint64_t chunks = PF_CHUNKS_COUNT(header->data_size);

    if (chunks == 0) /* no chunks to break */
        return 0;

#define SET_PTR(mem, idx) chunk = (pf_chunk_t*)(((uint8_t*)mem) + PF_CHUNK_OFFSET(idx));

    uint64_t idx = 0;
    uint64_t chunk_size = PF_CHUNK_DATA_SIZE(header->data_size, idx);
    BREAK_CHUNK("chunk_number_1", "invalid number (0->1)", true,
        {SET_PTR(output, idx); chunk->chunk_number = 1;});

    BREAK_CHUNK("chunk_number_2", "invalid number (0->max)", true,
        {SET_PTR(output, idx); chunk->chunk_number = UINT64_MAX;});

    BREAK_CHUNK("chunk_iv", "invalid IV", false,
        {SET_PTR(output, idx); chunk->chunk_iv[PF_IV_SIZE-1] ^= 1;});

    /* padding being zero is not enforced */
    BREAK_CHUNK("chunk_padding_1", "non-zero padding[0]", true,
        {SET_PTR(output, idx); chunk->padding[0] = 0xf0;});

    /* padding being zero is not enforced */
    BREAK_CHUNK("chunk_padding_2", "non-zero padding[7]", true,
        {SET_PTR(output, idx); chunk->padding[7] = 0x01;});

    BREAK_CHUNK("chunk_data_1", "invalid data[0]", false,
        {SET_PTR(output, idx); chunk->chunk_data[0] ^= 0xf0;});

    BREAK_CHUNK("chunk_data_2", "invalid data[size-1]", false,
        {SET_PTR(output, idx); chunk->chunk_data[chunk_size-1] ^= 0x01;});

    BREAK_CHUNK("chunk_mac", "invalid MAC", false,
        {SET_PTR(output, idx); chunk->chunk_mac[0] ^= 1;});

    if (chunks > 1) {
        idx = 1;
        chunk_size = PF_CHUNK_DATA_SIZE(header->data_size, idx);
        BREAK_CHUNK("chunk_number_3", "invalid number (1->0)", true,
            {SET_PTR(output, idx); chunk->chunk_number = 0;});

        BREAK_CHUNK("chunk_number_4", "invalid number (1->-1)", true,
            {SET_PTR(output, idx); chunk->chunk_number = -1;});

        /* reorder chunks */
        BREAK_CHUNK("chunk_reorder", "reordered chunks (0<->1)", false,
            {
                SET_PTR(output, 1); /* 0->1 */
                memcpy(chunk, (uint8_t*)input + PF_CHUNK_OFFSET(0), PF_CHUNK_SIZE);
                SET_PTR(output, 0); /* 1->0 */
                memcpy(chunk, (uint8_t*)input + PF_CHUNK_OFFSET(1), PF_CHUNK_SIZE);
            });
    }

    /* last chunk is not full? */
    SET_PTR(input, chunks-1); /* check last chunk size */
    idx = chunks - 1;
    chunk_size = PF_CHUNK_DATA_SIZE(header->data_size, idx);
    if (chunk_size != PF_CHUNK_DATA_MAX) {
        /* padding being zero is not enforced */
        BREAK_CHUNK("chunk_data_3", "non-zero data[size+1]", false,
            {SET_PTR(output, idx); chunk->chunk_data[chunk_size+1] = 1;});

        /* padding being zero is not enforced */
        BREAK_CHUNK("chunk_data_4", "non-zero data[max size-1]", false,
            {SET_PTR(output, idx); chunk->chunk_data[PF_CHUNK_DATA_MAX-1] = 1;});
    }

    ret = 0;
out:
    return ret;
}

int main(int argc, char *argv[]) {
    int ret             = -1;
    int this_option     = 0;
    char* input_path    = NULL;
    char* output_dir    = NULL;
    char* output_path   = NULL;
    char* wrap_key_path = NULL;
    int input_fd        = -1;
    void* input         = MAP_FAILED;
    uint8_t wrap_key[PF_WRAP_KEY_SIZE];

    while (true) {
        this_option = getopt_long(argc, argv, "i:o:w:vh", g_options, NULL);
        if (this_option == -1)
            break;

        switch (this_option) {
            case 'i':
                input_path = optarg;
                break;
            case 'o':
                output_dir = optarg;
                break;
            case 'w':
                wrap_key_path = optarg;
                break;
            case 'v':
                set_verbose(true);
                break;
            case 'h':
                usage();
                exit(0);
            default:
                ERROR("Unknown option: %c\n", this_option);
                usage();
        }
    }

    if (!input_path) {
        ERROR("Input path not specified\n");
        usage();
        goto out;
    }

    if (!output_dir) {
        ERROR("Output path not specified\n");
        usage();
        goto out;
    }

    if (!wrap_key_path) {
        ERROR("Wrap key path not specified\n");
        usage();
        goto out;
    }

    input_fd = open(input_path, O_RDONLY);
    if (input_fd < 0) {
        ERROR("Failed to open input file '%s': %s\n", input_path, strerror(errno));
        goto out;
    }

    ssize_t input_size = get_file_size(input_fd);
    if (input_size < 0) {
        ERROR("Failed to stat input file '%s': %s\n", input_path, strerror(errno));
        goto out;
    }

    input = mmap(NULL, input_size, PROT_READ, MAP_PRIVATE, input_fd, 0);
    if (input == MAP_FAILED) {
        ERROR("Failed to mmap input file '%s': %s\n", input_path, strerror(errno));
        goto out;
    }

    load_wrap_key(wrap_key_path, wrap_key);

    const char* input_name = basename(input_path);
    size_t output_path_size = strlen(input_name) + strlen(output_dir) + 256;
    output_path = malloc(output_path_size);
    if (!output_path) {
        ERROR("No memory\n");
        goto out;
    }

    ret = tamper_truncate(input_name, input_size, input, output_dir, output_path, output_path_size);
    if (ret < 0)
        goto out;

    ret = tamper_header(input_name, input_size, input, wrap_key, output_dir, output_path, output_path_size);
    if (ret < 0)
        goto out;

    ret = tamper_chunk(input_name, input_size, input, wrap_key, output_dir, output_path, output_path_size);

out:
    if (input != MAP_FAILED)
        munmap(input, input_size);
    if (input_fd >= 0)
        close(input_fd);
    free(output_path);
    return ret;
}
