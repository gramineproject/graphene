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

#include <pal_internal.h>
#include <pal_security.h>
#include <pal_error.h>
#include <api.h>
#include <assert.h>

#include "enclave_ocalls.h"

static PAL_LOCK malloc_lock = LOCK_INIT;
static int pagesize = PRESET_PAGESIZE;

#define system_lock()   _DkSpinLock(&malloc_lock)
#define system_unlock() _DkSpinUnlock(&malloc_lock)

#define PAGE_SIZE pagesize

static inline void * __malloc (int size)
{
    void * addr = NULL;

    ocall_alloc_untrusted(size, &addr);
    return addr;
}

#define system_malloc(size) __malloc(size)

static inline void __free (void * addr, int size)
{
    ocall_unmap_untrusted(addr, size);
}

#define system_free(addr, size) __free(addr, size)

#include "slabmgr.h"

static SLAB_MGR untrusted_slabmgr = NULL;

void init_untrusted_slab_mgr (int pagesize)
{
    if (untrusted_slabmgr)
        return;

    untrusted_slabmgr = create_slab_mgr();
    if (!untrusted_slabmgr)
        init_fail(PAL_ERROR_NOMEM, "cannot initialize slab manager");
}

void * malloc_untrusted (int size)
{
    return slab_alloc(untrusted_slabmgr, size);
}

void free_untrusted (void * ptr)
{
    slab_free(untrusted_slabmgr, ptr);
}
