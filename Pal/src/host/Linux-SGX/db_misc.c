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
 * db_misc.c
 *
 * This file contains APIs for miscellaneous use.
 */

#include "pal_defs.h"
#include "pal_linux_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_error.h"
#include "pal_debug.h"
#include "pal_security.h"
#include "api.h"

#include <linux/time.h>
#include <asm/fcntl.h>

unsigned long _DkSystemTimeQuery (void)
{
    unsigned long microsec;
    int ret = ocall_gettime(&microsec);
    assert(!ret);
    return microsec;
}

int _DkRandomBitsRead (void * buffer, int size)
{
    int i = 0;

    for ( ; i < size ; i += 4) {
        uint32_t rand = rdrand();

        if (i + 4 <= size) {
            *(uint32_t *)(buffer + i) = rand;
        } else {
            switch (size - i) {
                case 3:
                    *(uint16_t *)(buffer + i) = rand & 0xffff;
                    i += 2;
                    rand >>= 16;
                case 1:
                    *(uint8_t *)(buffer + i) = rand & 0xff;
                    i++;
                    break;
                case 2:
                    *(uint16_t *)(buffer + i) = rand & 0xffff;
                    i += 2;
                    break;
            }
            break;
        }
    }
    return i;
}

int _DkInstructionCacheFlush (const void * addr, int size)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkSegmentRegisterSet (int reg, const void * addr)
{
    /* GS is internally used, denied any access to it */
    if (reg != PAL_SEGMENT_FS)
        return -PAL_ERROR_DENIED;

    SET_ENCLAVE_TLS(fsbase, (void *) addr);
    wrfsbase((uint64_t) addr);
    return 0;
}

int _DkSegmentRegisterGet (int reg, void ** addr)
{
    /* GS is internally used, denied any access to it */
    if (reg != PAL_SEGMENT_FS)
        return -PAL_ERROR_DENIED;

    *addr = (void *) GET_ENCLAVE_TLS(fsbase);
    return 0;
}

#define CPUID_CACHE_SIZE    64
#define CPUID_CACHE_INVALID ((unsigned int) -1)

static PAL_LOCK cpuid_cache_lock = LOCK_INIT;

static struct pal_cpuid {
    unsigned int recently;
    unsigned int leaf, subleaf;
    unsigned int values[4];
} pal_cpuid_cache[CPUID_CACHE_SIZE];

static int pal_cpuid_cache_top = 0;
static unsigned int pal_cpuid_clock = 0;

int get_cpuid_from_cache (unsigned int leaf, unsigned int subleaf,
                          unsigned int values[4])
{
    _DkInternalLock(&cpuid_cache_lock);

    for (int i = 0 ; i < pal_cpuid_cache_top ; i++)
        if (pal_cpuid_cache[i].leaf == leaf &&
            pal_cpuid_cache[i].subleaf == subleaf) {
            values[0] = pal_cpuid_cache[i].values[0];
            values[1] = pal_cpuid_cache[i].values[1];
            values[2] = pal_cpuid_cache[i].values[2];
            values[3] = pal_cpuid_cache[i].values[3];
            pal_cpuid_cache[i].recently = ++pal_cpuid_clock;
            _DkInternalUnlock(&cpuid_cache_lock);
            return 0;
        }

    _DkInternalUnlock(&cpuid_cache_lock);
    return -PAL_ERROR_DENIED;
}

void add_cpuid_to_cache (unsigned int leaf, unsigned int subleaf,
                         unsigned int values[4])
{
    struct pal_cpuid * chosen;
    _DkInternalLock(&cpuid_cache_lock);

    if (pal_cpuid_cache_top < CPUID_CACHE_SIZE) {
        for (int i = 0 ; i < pal_cpuid_cache_top ; i++)
            if (pal_cpuid_cache[i].leaf == leaf &&
                pal_cpuid_cache[i].subleaf == subleaf) {
                _DkInternalUnlock(&cpuid_cache_lock);
                return;
        }

        chosen = &pal_cpuid_cache[pal_cpuid_cache_top++];
    } else {
        unsigned int oldest_clock = pal_cpuid_cache[0].recently;
        chosen = &pal_cpuid_cache[0];

        if (pal_cpuid_cache[0].leaf == leaf &&
            pal_cpuid_cache[0].subleaf == subleaf) {
            _DkInternalUnlock(&cpuid_cache_lock);
            return;
        }

        for (int i = 1 ; i < pal_cpuid_cache_top ; i++) {
            if (pal_cpuid_cache[i].leaf == leaf &&
                pal_cpuid_cache[i].subleaf == subleaf) {
                _DkInternalUnlock(&cpuid_cache_lock);
                return;
            }

            if (pal_cpuid_cache[i].recently > oldest_clock) {
                chosen = &pal_cpuid_cache[i];
                oldest_clock = pal_cpuid_cache[i].recently;
            }
        }
    }

    chosen->leaf = leaf;
    chosen->subleaf = subleaf;
    chosen->values[0] = values[0];
    chosen->values[1] = values[1];
    chosen->values[2] = values[2];
    chosen->values[3] = values[3];
    chosen->recently = ++pal_cpuid_clock;

    _DkInternalUnlock(&cpuid_cache_lock);
}

int _DkCpuIdRetrieve (unsigned int leaf, unsigned int subleaf,
                      unsigned int values[4])
{
    if (leaf != 0x4 && leaf != 0x7 && leaf != 0xb)
        subleaf = 0;

    if (!get_cpuid_from_cache(leaf, subleaf, values))
        return 0;

    if (ocall_cpuid(leaf, subleaf, values) < 0)
        return -PAL_ERROR_DENIED;

    add_cpuid_to_cache(leaf, subleaf, values);
    return 0;
}
