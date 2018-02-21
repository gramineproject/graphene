/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2014 Stony Brook University
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
 * shim_random.c
 *
 * This file contains codes for generating random numbers.
 */

#include <shim_internal.h>
#include <shim_utils.h>
#include <shim_checkpoint.h>

#include <pal.h>

static LOCKTYPE randgen_lock;
static unsigned long randval;

int init_randgen (void)
{
    if (DkRandomBitsRead (&randval, sizeof(randval)) < sizeof(randval))
        return -EACCES;

    debug("initial random value: %08llx\n", randval);
    create_lock(randgen_lock);
    return 0;
}

void getrand (void * buffer, size_t size)
{
    size_t bytes = 0;
    lock(randgen_lock);

    while (bytes + sizeof(uint64_t) <= size) {
        *(uint64_t *) (buffer + bytes) = randval;
        bytes += sizeof(uint64_t);
        randval = hash64(randval);
    }

    if (bytes < size) {
        memcpy(buffer + bytes, &randval, size - bytes);
        randval = hash64(randval);
    }

    unlock(randgen_lock);
}
extern_alias(getrand);
