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

int object_wait_with_retry(PAL_HANDLE handle)
{
    PAL_HANDLE ret;
    do {
        ret = DkObjectsWaitAny(1, &handle, NO_TIMEOUT);
    } while (ret == NULL && (PAL_NATIVE_ERRNO == PAL_ERROR_INTERRUPTED ||
                             PAL_NATIVE_ERRNO == PAL_ERROR_TRYAGAIN));
    if (ret == NULL) {
        debug("waiting on %p resulted in error %s",
              handle, PAL_STRERROR(PAL_NATIVE_ERRNO));
        return -PAL_NATIVE_ERRNO;
    }
    assert(ret == handle);
    return 0;
}
