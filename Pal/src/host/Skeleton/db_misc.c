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

#include "api.h"
#include "assert.h"
#include "pal.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"

void _DkInternalLock(PAL_LOCK* lock) {
    __abort();
}

void _DkInternalUnlock(PAL_LOCK* lock) {
    __abort();
}

bool _DkInternalIsLocked(PAL_LOCK* lock) {
    __abort();
}

unsigned long _DkSystemTimeQuery(void) {
    return 0;
}

size_t _DkRandomBitsRead(void* buffer, size_t size) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkSegmentRegisterSet(int reg, const void* addr) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkSegmentRegisterGet(int reg, void** addr) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkInstructionCacheFlush(const void* addr, int size) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkCpuIdRetrieve(unsigned int leaf, unsigned int subleaf, unsigned int values[4]) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkAttestationQuote(PAL_PTR report_data, PAL_NUM report_data_size, PAL_PTR quote,
                        PAL_NUM* quote_size) {
    __UNUSED(report_data);
    __UNUSED(report_data_size);
    __UNUSED(quote);
    __UNUSED(quote_size);
    return -PAL_ERROR_NOTIMPLEMENTED;
}
