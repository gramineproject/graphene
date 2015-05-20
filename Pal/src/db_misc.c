/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2014 OSCAR lab, Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * db_misc.c
 *
 * This file contains APIs for miscellaneous use.
 */

#include "pal_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_error.h"
#include "api.h"

PAL_NUM DkSystemTimeQuery (void)
{
    store_frame(SystemTimeQuery);
    unsigned long time = _DkSystemTimeQuery();
    return time;
}

static PAL_LOCK lock = LOCK_INIT;
static unsigned long seed;

int _DkFastRandomBitsRead (void * buffer, int size)
{
    unsigned long rand;
    int bytes = 0;

    _DkInternalLock(&lock);
    rand = seed;
    while (!seed) {
        _DkInternalUnlock(&lock);
        if (_DkRandomBitsRead(&rand, sizeof(rand)) < sizeof(rand))
            return -PAL_ERROR_DENIED;

        _DkInternalLock(&lock);
        seed = rand;
    }

    do {
        if (bytes + sizeof(rand) <= size) {
            *(unsigned long *) (buffer + bytes) = rand;
            bytes += sizeof(rand);
        } else {
            for (int i = 0 ; i < size - bytes ; i++)
                *(unsigned char *) (buffer + bytes + i) = ((unsigned char *) &rand)[i];
            bytes = size;
        }
        do {
            rand = hash64(rand);
        } while (!rand);
    } while (bytes < size);

    seed = rand;
    _DkInternalUnlock(&lock);

    return bytes;
}

PAL_NUM DkRandomBitsRead (PAL_BUF buffer, PAL_NUM size)
{
    store_frame(RandomBitsRead);

    if (!buffer || !size)
        leave_frame(0, PAL_ERROR_INVAL);

    int ret = _DkRandomBitsRead(buffer, size);

    if (ret < 0)
        leave_frame(0, -ret);

    leave_frame(ret, 0);
}

PAL_PTR DkSegmentRegister (PAL_FLG reg, PAL_PTR addr)
{
    store_frame(SegmentRegister);
    int ret;

    if (addr) {
        ret = _DkSegmentRegisterSet(reg, addr);
        if (ret < 0)
            leave_frame(NULL, -ret);
        leave_frame(addr, 0);
    } else {
        ret = _DkSegmentRegisterGet(reg, (void **) &addr);
        if (ret < 0)
            leave_frame(NULL, -ret);
        leave_frame(addr, 0);
    }
}

PAL_BOL DkInstructionCacheFlush (PAL_PTR addr, PAL_NUM size)
{
    store_frame(InstructionCacheFlush);

    if (!addr || !size)
        leave_frame(PAL_FALSE, PAL_ERROR_INVAL);

    int ret = _DkInstructionCacheFlush(addr, size);

    if (ret < 0)
        leave_frame(PAL_FALSE, -ret);

    leave_frame(PAL_TRUE, 0);
}

PAL_NUM DkMemoryAvailableQuota (void)
{
    store_frame(MemoryAvailableQuota);

    long quota = _DkMemoryAvailableQuota();

    leave_frame((quota < 0) ? 0 : quota, 0);
}
