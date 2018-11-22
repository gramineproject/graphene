/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2018 Intel Corporation
                      Isaku Yamahata <isaku.yamahata at gmail.com>
                                     <isaku.yamahata at intel.com>
   All Rights Reserved.

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
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <pal.h>

#include <shim_internal.h>

int object_wait_one_safe(PAL_HANDLE handle)
{
    for (;;) {
        PAL_HANDLE ret;
        ret = DkObjectsWaitAny(1, &handle, NO_TIMEOUT);
        if (ret == NULL) {
            if (PAL_NATIVE_ERRNO == PAL_ERROR_INTERRUPTED ||
                PAL_NATIVE_ERRNO == PAL_ERROR_TRYAGAIN)
                continue;

            debug("waiting on %p results in error %s",
                  handle, PAL_STRERROR(PAL_NATIVE_ERRNO));
            return -PAL_NATIVE_ERRNO;
        }

        assert (ret == handle);
        return 0;
    }
}
