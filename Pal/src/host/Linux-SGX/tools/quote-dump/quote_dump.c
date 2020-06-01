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

#include "attestation.h"
#include "util.h"

struct option g_options[] = {
    { "help", no_argument, 0, 'h' },
    { "msb", no_argument, 0, 'm' },
    { 0, 0, 0, 0 }
};

static void usage(const char* exec) {
    INFO("Usage: %s [options] <quote path>\n", exec);
    INFO("Available options:\n");
    INFO("  --help, -h  Display this help\n");
    INFO("  --msb, -m   Display hex strings in big-endian order\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        usage(argv[0]);
        return -1;
    }

    endianness_t endian = ENDIAN_LSB;

    int option = 0;
    // parse command line
    while (true) {
        option = getopt_long(argc, argv, "hm", g_options, NULL);
        if (option == -1)
            break;

        switch (option) {
            case 'h':
                usage(argv[0]);
                return 0;
            case 'm':
                endian = ENDIAN_MSB;
                break;
            default:
                usage(argv[0]);
                return -1;
        }
    }

    if (optind >= argc) {
        ERROR("Quote path not specified\n");
        usage(argv[0]);
        return -1;
    }

    const char* path = argv[optind++];

    ssize_t quote_size = 0;
    uint8_t* quote = read_file(path, &quote_size);
    if (!quote)
        return -1;

    set_endianness(endian);
    display_quote(quote, quote_size);
    return 0;
}
