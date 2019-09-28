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
 * db_main.c
 *
 * This file contains the main function of the PAL loader, which loads and
 * processes environment, arguments and manifest.
 */

#include "pal_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_debug.h"
#include "pal_error.h"
#include "api.h"

void __stack_chk_fail(void)
{
}

/* must implement "pal_start", and call "pal_main" inside */
void pal_start (void);

unsigned long _DkGetPagesize (void)
{
    return 0;
}

unsigned long _DkGetAllocationAlignment (void)
{
    return 0;
}

void _DkGetAvailableUserAddressRange (PAL_PTR * start, PAL_PTR * end,
                                      PAL_PTR * hole_start, PAL_PTR * hole_end)
{
    /* needs to be implemented */
}

PAL_NUM _DkGetProcessId (void)
{
    return 0;
}

PAL_NUM _DkGetHostId (void)
{
    return 0;
}

int _DkGetCPUInfo (PAL_CPU_INFO * ci)
{
    /* needs to be implemented */
    return 0;
}
