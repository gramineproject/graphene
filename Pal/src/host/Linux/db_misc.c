/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * db_misc.c
 *
 * This file contains APIs for miscellaneous use.
 */

#include <asm/fcntl.h>
#include <linux/time.h>

#include "api.h"
#include "pal.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_security.h"

int __gettimeofday(struct timeval* tv, struct timezone* tz);

unsigned long _DkSystemTimeQueryEarly(void) {
#if USE_CLOCK_GETTIME == 1
    struct timespec time;
    int ret;

    ret = INLINE_SYSCALL(clock_gettime, 2, CLOCK_REALTIME, &time);

    /* Come on, gettimeofday mostly never fails */
    if (IS_ERR(ret))
        return 0;

    /* in microseconds */
    return 1000000ULL * time.tv_sec + time.tv_nsec / 1000;
#else
    struct timeval time;
    int ret;

    ret = INLINE_SYSCALL(gettimeofday, 2, &time, NULL);

    /* Come on, gettimeofday mostly never fails */
    if (IS_ERR(ret))
        return 0;

    /* in microseconds */
    return 1000000ULL * time.tv_sec + time.tv_usec;
#endif
}

unsigned long _DkSystemTimeQuery(void) {
#if USE_CLOCK_GETTIME == 1
    struct timespec time;
    int ret;

#if USE_VDSO_GETTIME == 1
    if (g_linux_state.vdso_clock_gettime) {
        ret = g_linux_state.vdso_clock_gettime(CLOCK_REALTIME, &time);
    } else {
#endif
        ret = INLINE_SYSCALL(clock_gettime, 2, CLOCK_REALTIME, &time);
#if USE_VDSO_GETTIME == 1
    }
#endif

    /* Come on, gettimeofday mostly never fails */
    if (IS_ERR(ret))
        return 0;

    /* in microseconds */
    return 1000000ULL * time.tv_sec + time.tv_nsec / 1000;
#else
    struct timeval time;
    int ret;

#if USE_VDSO_GETTIME == 1
    if (g_linux_state.vdso_gettimeofday) {
        ret = g_linux_state.vdso_gettimeofday(&time, NULL);
    } else {
#endif
#if USE_VSYSCALL_GETTIME == 1
        ret = __gettimeofday(&time, NULL);
#else
        ret = INLINE_SYSCALL(gettimeofday, 2, &time, NULL);
#endif
#if USE_VDSO_GETTIME == 1
    }
#endif

    /* Come on, gettimeofday mostly never fails */
    if (IS_ERR(ret))
        return 0;

    /* in microseconds */
    return 1000000ULL * time.tv_sec + time.tv_usec;
#endif
}

#if USE_ARCH_RD_RAND != 1
size_t _DkRandomBitsRead(void* buffer, size_t size) {
    if (!g_pal_sec.random_device) {
        int fd = INLINE_SYSCALL(open, 3, RANDGEN_DEVICE, O_RDONLY, 0);
        if (IS_ERR(fd))
            return -PAL_ERROR_DENIED;

        g_pal_sec.random_device = fd;
    }

    size_t total_bytes = 0;
    do {
        int bytes = INLINE_SYSCALL(read, 3, g_pal_sec.random_device, buffer + total_bytes,
                                   size - total_bytes);
        if (IS_ERR(bytes))
            return -PAL_ERROR_DENIED;

        total_bytes += (size_t)bytes;
    } while (total_bytes < size);

    return 0;
}
#endif

int _DkInstructionCacheFlush(const void* addr, int size) {
    __UNUSED(addr);
    __UNUSED(size);

    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkAttestationReport(PAL_PTR user_report_data, PAL_NUM* user_report_data_size,
                         PAL_PTR target_info, PAL_NUM* target_info_size,
                         PAL_PTR report, PAL_NUM* report_size) {
    __UNUSED(user_report_data);
    __UNUSED(user_report_data_size);
    __UNUSED(target_info);
    __UNUSED(target_info_size);
    __UNUSED(report);
    __UNUSED(report_size);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkAttestationQuote(PAL_PTR user_report_data, PAL_NUM user_report_data_size,
                        PAL_PTR quote, PAL_NUM* quote_size) {
    __UNUSED(user_report_data);
    __UNUSED(user_report_data_size);
    __UNUSED(quote);
    __UNUSED(quote_size);
    return -PAL_ERROR_NOTIMPLEMENTED;
}
