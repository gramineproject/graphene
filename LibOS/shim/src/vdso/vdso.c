/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2018 Intel Corporation
 *                    Isaku Yamahata <isaku.yamahata at gmail.com>
 *                                   <isaku.yamahata at intel.com>
 */

#include "vdso.h"

/*
 * The symbols below need to be exported for libsysdb to inject those values,
 * but relocation (.rela.dyn section) isn't wanted in the code generation.
 */
#define EXPORT_SYMBOL(name) extern __typeof__(name) __vdso_##name __attribute__((alias(#name)))

static int (*shim_clock_gettime)(clockid_t clock, struct timespec* t)    = NULL;
static int (*shim_gettimeofday)(struct timeval* tv, struct timezone* tz) = NULL;
static time_t (*shim_time)(time_t* t)                                    = NULL;
static long (*shim_getcpu)(unsigned* cpu, struct getcpu_cache* unused)   = NULL;

EXPORT_SYMBOL(shim_clock_gettime);
EXPORT_SYMBOL(shim_gettimeofday);
EXPORT_SYMBOL(shim_time);
EXPORT_SYMBOL(shim_getcpu);

#define EXPORT_WEAK_SYMBOL(name) \
    __typeof__(__vdso_##name) name __attribute__((weak, alias("__vdso_" #name)))

int __vdso_clock_gettime(clockid_t clock, struct timespec* t) {
    if (shim_clock_gettime)
        return (*shim_clock_gettime)(clock, t);
    return -ENOSYS;
}
EXPORT_WEAK_SYMBOL(clock_gettime);

int __vdso_gettimeofday(struct timeval* tv, struct timezone* tz) {
    if (shim_gettimeofday)
        return (*shim_gettimeofday)(tv, tz);
    return -ENOSYS;
}
EXPORT_WEAK_SYMBOL(gettimeofday);

time_t __vdso_time(time_t* t) {
    if (shim_time)
        return (*shim_time)(t);
    return -ENOSYS;
}
EXPORT_WEAK_SYMBOL(time);

long __vdso_getcpu(unsigned* cpu, struct getcpu_cache* unused) {
    if (shim_getcpu)
        return (*shim_getcpu)(cpu, unused);
    return -ENOSYS;
}
EXPORT_WEAK_SYMBOL(getcpu);
