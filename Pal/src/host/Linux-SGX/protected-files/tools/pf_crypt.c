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

#include <getopt.h>
#include <stdlib.h>

#include "pf_util.h"
#include "util.h"

/* Command line options */
struct option g_options[] = {
    { "input", required_argument, 0, 'i' },
    { "output", required_argument, 0, 'o' },
    { "prefix", required_argument, 0, 'p' },
    { "wrap-key", required_argument, 0, 'w' },
    { "verify", no_argument, 0, 'V' },
    { "verbose", no_argument, 0, 'v' },
    { "help", no_argument, 0, 'h' },
    { 0, 0, 0, 0 }
};

void usage() {
    INFO("\nUsage: pf_crypt mode [options]\n");
    INFO("Available modes:\n");
    INFO("  gen-key                 Generate and save wrap key to file\n");
    INFO("  encrypt                 Encrypt plaintext files\n");
    INFO("  decrypt                 Decrypt encrypted files\n");
    INFO("\nAvailable general options:\n");
    INFO("  --help, -h              Display this help\n");
    INFO("  --verbose, -v           Verbose output\n");
    INFO("\nAvailable gen-key options:\n");
    INFO("  --wrap-key, -w PATH     Path to wrap key file\n");
    INFO("\nAvailable encrypt options:\n");
    INFO("  --input, -i PATH        Single file or directory with input files to convert\n");
    INFO("  --output, -o PATH       Single file or directory to write output files to\n");
    INFO("  --prefix, -p PATH       Path prefix for protected files that the payload manifest expects\n");
    INFO("  --wrap-key, -w PATH     Path to wrap key file, must exist\n");
    INFO("\nAvailable decrypt options:\n");
    INFO("  --input, -i PATH        Single file or directory with input files to convert\n");
    INFO("  --output, -o PATH       Single file or directory to write output files to\n");
    INFO("  --wrap-key, -w PATH     Path to wrap key file, must exist\n");
    INFO("  --verify, -V            (optional) Verify that input path matches PF's allowed paths\n");
}

int main(int argc, char *argv[]) {
    int ret             = -1;
    int this_option     = 0;
    char* input_path    = NULL;
    char* output_path   = NULL;
    char* wrap_key_path = NULL;
    char* prefix        = NULL;
    char* mode          = NULL;
    bool verify         = false;

    while (true) {
        this_option = getopt_long(argc, argv, "i:o:p:w:Vvh", g_options, NULL);
        if (this_option == -1)
            break;

        switch (this_option) {
            case 'i':
                input_path = optarg;
                break;
            case 'o':
                output_path = optarg;
                break;
            case 'p':
                prefix = optarg;
                break;
            case 'w':
                wrap_key_path = optarg;
                break;
            case 'v':
                set_verbose(true);
                break;
            case 'V':
                verify = true;
                break;
            case 'h':
                usage();
                exit(0);
            default:
                ERROR("Unknown option: %c\n", this_option);
                usage();
        }
    }

    if (optind >= argc) {
        ERROR("Mode not specified\n");
        usage();
        goto out;
    }

    if (!wrap_key_path) {
        ERROR("Wrap key path not specified\n");
        goto out;
    }

    mode = argv[optind];
    pf_init();

    switch (mode[0]) {
    case 'g': /* gen-key */
        ret = pf_generate_wrap_key(wrap_key_path);
        break;

    case 'e': /* encrypt */
        if (!input_path || !output_path || !prefix) {
            ERROR("Input/output path or prefix not specified\n");
            usage();
            goto out;
        }
        ret = pf_encrypt_files(input_path, output_path, prefix, wrap_key_path);
        break;

    case 'd': /* decrypt */
        if (!input_path || !output_path) {
            ERROR("Input or output path not specified\n");
            usage();
            goto out;
        }
        ret = pf_decrypt_files(input_path, output_path, verify, wrap_key_path);
        break;

    default:
        usage();
        goto out;
    }

out:
    return ret;
}
