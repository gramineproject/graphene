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
 * db_mutex.c
 *
 * This file contains APIs that provide operations of (futex based) mutexes.
 * Based on "Mutexes and Condition Variables using Futexes"
 * (http://locklessinc.com/articles/mutex_cv_futex)
 */

#include "pal_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_error.h"
#include "api.h"

int _DkMutexLockTimeout (struct mutex_handle * mut, int timeout)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkMutexLock (struct mutex_handle * mut)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkMutexUnlock (struct mutex_handle * mut)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}
