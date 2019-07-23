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

#include <shim_types.h>

int (*__vdso_shim_clock_gettime)(clockid_t clock, struct timespec* t)    = NULL;
int (*__vdso_shim_gettimeofday)(struct timeval* tv, struct timezone* tz) = NULL;
time_t (*__vdso_shim_time)(time_t* t) = NULL;
long (*__vdso_shim_getcpu)(unsigned* cpu, struct getcpu_cache* unused) = NULL;

int __vdso_clock_gettime(clockid_t clock, struct timespec* t) {
    if (__vdso_shim_clock_gettime)
        return (*__vdso_shim_clock_gettime)(clock, t);
    return -ENOSYS;
}
int clock_gettime(clockid_t clock, struct timespec* t)
    __attribute__((weak, alias("__vdso_clock_gettime")));

int __vdso_gettimeofday(struct timeval* tv, struct timezone* tz) {
    if (__vdso_shim_gettimeofday)
        return (*__vdso_shim_gettimeofday)(tv, tz);
    return -ENOSYS;
}
int gettimeofday(struct timeval* tv, struct timezone* tz)
    __attribute__((weak, alias("__vdso_gettimeofday")));

time_t __vdso_time(time_t* t) {
    if (__vdso_shim_time)
        return (*__vdso_shim_time)(t);
    return -ENOSYS;
}
time_t time(time_t* t) __attribute__((weak, alias("__vdso_time")));

long __vdso_getcpu(unsigned* cpu, struct getcpu_cache* unused) {
    if (__vdso_shim_getcpu)
        return (*__vdso_shim_getcpu)(cpu, unused);
    return -ENOSYS;
}
long getcpu(unsigned* cpu, struct getcpu_cache* unused)
    __attribute__((weak, alias("__vdso_getcpu")));
