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

#include <stdlib.h>

#include "attestation.h"
#include "util.h"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        ERROR("Usage: %s <filename>\n", argv[0]);
        return -EINVAL;
    }

    const char* path = argv[1];

    ssize_t quote_size = 0;
    uint8_t* quote = read_file(path, &quote_size);
    if (!quote)
        return -1;

    display_quote(quote, quote_size);
    return 0;
}
