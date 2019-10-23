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

#include "../protected_files.h"
#include "util.h"

/* Tamper with a PF in various ways for testing purposes.
   Wrap key is needed, some modifications change the key and/or (meta)data
   to create invalid MACs etc. */

// Command line options
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
    INFO("\nAvailable options:\n");
    INFO("  --help, -h           Display this help\n");
    INFO("  --verbose, -v        Enable verbose output\n");
    INFO("  --wrap-key, -w PATH  Path to wrap key file\n");
    INFO("  --input, -i PATH     Source file to be tampered with (must be a valid PF)\n");
    INFO("  --output, -o PATH    Directory where modified files will be written to\n");
}

int tamper_truncate(const char* output_dir, const char* input_name, ssize_t input_size, void* input) {
    int ret = -1;
    ssize_t output_path_size = strlen(input_name) + strlen(output_dir) + 256;
    char* output_path = NULL;
    const ssize_t min_size = PF_CHUNKS_OFFSET + offsetof(pf_chunk_t, chunk_data) + 7;

    if (input_size < min_size) {
        ERROR("Input size %zu too small, need at least %zu\n", input_size, min_size);
        goto out;
    }

    output_path = malloc(output_path_size);
    if (!output_path) {
        ERROR("No memory\n");
        goto out;
    }

    snprintf(output_path, output_path_size, "%s/%s.trunc_zero", output_dir, input_name);
    INFO("[*] Zero-size file: %s\n", output_path);
    ret = write_file(output_path, 0, input);
    if (ret < 0)
        goto out;

    snprintf(output_path, output_path_size, "%s/%s.trunc_header", output_dir, input_name);
    INFO("[*] Truncated header: %s\n", output_path);
    ret = write_file(output_path, PF_CHUNKS_OFFSET / 2, input);
    if (ret < 0)
        goto out;
    
    snprintf(output_path, output_path_size, "%s/%s.trunc_chunk_metadata", output_dir, input_name);
    INFO("[*] Truncated chunk (metadata): %s\n", output_path);
    ret = write_file(output_path, PF_CHUNKS_OFFSET + 10, input);
    if (ret < 0)
        goto out;
    
    snprintf(output_path, output_path_size, "%s/%s.trunc_chunk_data", output_dir, input_name);
    INFO("[*] Truncated chunk (data): %s\n", output_path);
    ret = write_file(output_path, min_size, input);
    if (ret < 0)
        goto out;
    
    ret = 0;
out:
    free(output_path);
    return ret;
}

int main(int argc, char *argv[]) {
    int ret             = -1;
    int this_option     = 0;
    char* input_path    = NULL;
    char* output_path   = NULL;
    char* wrap_key_path = NULL;
    int input_fd        = -1;
    void* input         = MAP_FAILED;

    // Parse command line
    while (true) {
        this_option = getopt_long(argc, argv, "i:o:w:vh", g_options, NULL);
        if (this_option == -1)
            break;

        switch (this_option) {
            case 'i':
                input_path = optarg;
                break;
            case 'o':
                output_path = optarg;
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

    if (!output_path) {
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

    const char* input_name = basename(input_path);
    ret = tamper_truncate(output_path, input_name, input_size, input);

    ret = 0;
out:
    if (input != MAP_FAILED)
        munmap(input, input_size);
    if (input_fd >= 0)
        close(input_fd);
    return ret;
}
