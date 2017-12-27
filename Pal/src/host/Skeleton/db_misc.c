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

int _DkInternalLock (PAL_LOCK * lock)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkInternalUnlock (PAL_LOCK * lock)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

unsigned long _DkSystemTimeQuery (void)
{
    return 0;
}

int _DkRandomBitsRead (void * buffer, int size)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkSegmentRegisterSet (int reg, const void * addr)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkSegmentRegisterGet (int reg, void ** addr)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkInstructionCacheFlush (const void * addr, int size)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}
