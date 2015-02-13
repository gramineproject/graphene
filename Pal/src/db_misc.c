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
static unsigned long randval = 0;

static int init_randgen (void)
{
    unsigned long val;

    if (_DkRandomBitsRead(&val, sizeof(val)) < sizeof(val))
        return -PAL_ERROR_DENIED;

    _DkInternalLock(&lock);
    randval = val;
    _DkInternalUnlock(&lock);
    return 0;
}

int getrand (void * buffer, int size)
{
    unsigned long val;
    int bytes = 0;

    _DkInternalLock(&lock);
    while (!randval) {
        _DkInternalUnlock(&lock);
        if (init_randgen() < 0)
            return -PAL_ERROR_DENIED;
        _DkInternalLock(&lock);
    }

    val = randval;
    randval++;
    _DkInternalUnlock(&lock);

    while (bytes + sizeof(unsigned long) <= size) {
        *(unsigned long *) (buffer + bytes) = val;
        val = hash64(val);
        bytes += sizeof(unsigned long);
    }

    if (bytes < size) {
        switch (size - bytes) {
            case 4:
                *(unsigned int *) (buffer + bytes) = randval & 0xffffffff;
                bytes += 4;
                break;

            case 2:
                *(unsigned short *) (buffer + bytes) = randval & 0xffff;
                bytes += 2;
                break;

            case 1:
                *(unsigned char *) (buffer + bytes) = randval & 0xff;
                bytes++;
                break;

            default: break;
        }
        randval = hash64(randval);
    }

    _DkInternalLock(&lock);
    randval = val;
    _DkInternalUnlock(&lock);

    return bytes;
}

PAL_NUM DkRandomBitsRead (PAL_BUF buffer, PAL_NUM size)
{
    store_frame(RandomBitsRead);

    if (!buffer || !size) {
        notify_failure(PAL_ERROR_INVAL);
        return 0;
    }

    int ret = _DkRandomBitsRead(buffer, size);

    if (ret < 0) {
        notify_failure(-ret);
        return 0;
    }

    return ret;
}

PAL_BOL DkInstructionCacheFlush (PAL_PTR addr, PAL_NUM size)
{
    store_frame(InstructionCacheFlush);

    if (!addr || !size) {
        notify_failure(PAL_ERROR_INVAL);
        return PAL_FALSE;
    }

    int ret = _DkInstructionCacheFlush(addr, size);

    if (ret < 0) {
        notify_failure(-ret);
        return PAL_FALSE;
    }

    return PAL_TRUE;
}
