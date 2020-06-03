/*
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

#ifndef _DB_RTLD_H_
#define _DB_RTLD_H_

#include "pal_linux_defs.h"
#include "sysdeps/generic/ldsodefs.h"

#if USE_VDSO_GETTIME == 1
void setup_vdso_map(ElfW(Addr) addr);
#endif /* USE_VDSO_GETTIME */

#endif /* _DB_RTLD_H_ */
