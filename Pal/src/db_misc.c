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
#include "pal.h"
#include "pal_internal.h"
#include "pal_error.h"
#include "api.h"

PAL_NUM DkSystemTimeQuery (void)
{
    ENTER_PAL_CALL(DkSystemTimeQuery);
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
            *(unsigned long *) ((char *) buffer + bytes) = rand;
            bytes += sizeof(rand);
        } else {
            for (int i = 0 ; i < size - bytes ; i++)
                *(unsigned char *) ((char *) buffer + bytes + i) = ((unsigned char *) &rand)[i];
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

PAL_NUM DkRandomBitsRead (PAL_PTR buffer, PAL_NUM size)
{
    ENTER_PAL_CALL(DkRandomBitsRead);

    if (!buffer || !size) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL_RETURN(0);
    }

    int ret = _DkRandomBitsRead((void *) buffer, size);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        ret = 0;
    }

    LEAVE_PAL_CALL_RETURN(ret);
}

PAL_PTR DkSegmentRegister (PAL_FLG reg, PAL_PTR addr)
{
    ENTER_PAL_CALL(DkSegmentRegister);
    void * seg_addr = (void *) addr;
    int ret;

    if (addr) {
        ret = _DkSegmentRegisterSet(reg, seg_addr);
    } else {
        ret = _DkSegmentRegisterGet(reg, &seg_addr);
    }

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        seg_addr = NULL;
    }

    LEAVE_PAL_CALL_RETURN((PAL_PTR) seg_addr);
}

PAL_BOL DkInstructionCacheFlush (PAL_PTR addr, PAL_NUM size)
{
    ENTER_PAL_CALL(DkInstructionCacheFlush);

    if (!addr || !size) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    int ret = _DkInstructionCacheFlush((void *) addr, size);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    LEAVE_PAL_CALL_RETURN(PAL_TRUE);
}

PAL_NUM DkMemoryAvailableQuota (void)
{
    ENTER_PAL_CALL(DkMemoryAvailableQuota);

    long quota = _DkMemoryAvailableQuota();
    if (quota < 0)
        quota = 0;

    LEAVE_PAL_CALL_RETURN((PAL_NUM) quota);
}

PAL_BOL
DkCpuIdRetrieve (PAL_IDX leaf, PAL_IDX subleaf, PAL_IDX values[4])
{
    ENTER_PAL_CALL(DkCpuIdRetrieve);

    unsigned int vals[4];
    int ret = _DkCpuIdRetrieve(leaf, subleaf, vals);
    if (ret < 0) {
        _DkRaiseFailure(-ret);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    values[0] = vals[0];
    values[1] = vals[1];
    values[2] = vals[2];
    values[3] = vals[3];

    LEAVE_PAL_CALL_RETURN(PAL_TRUE);
}
