/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
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

int _DkSystemTimeQuery(uint64_t* out_usec) {
    struct timespec time;
    int ret;

    if (g_linux_state.vdso_clock_gettime) {
        ret = g_linux_state.vdso_clock_gettime(CLOCK_REALTIME, &time);
    } else {
        ret = INLINE_SYSCALL(clock_gettime, 2, CLOCK_REALTIME, &time);
    }

    if (IS_ERR(ret))
        return ret;

    /* in microseconds */
    *out_usec = 1000000 * (uint64_t)time.tv_sec + time.tv_nsec / 1000;
    return 0;
}

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

int _DkInstructionCacheFlush(const void* addr, int size) {
    __UNUSED(addr);
    __UNUSED(size);

    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkAttestationReport(PAL_PTR user_report_data, PAL_NUM* user_report_data_size,
                         PAL_PTR target_info, PAL_NUM* target_info_size, PAL_PTR report,
                         PAL_NUM* report_size) {
    __UNUSED(user_report_data);
    __UNUSED(user_report_data_size);
    __UNUSED(target_info);
    __UNUSED(target_info_size);
    __UNUSED(report);
    __UNUSED(report_size);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkAttestationQuote(PAL_PTR user_report_data, PAL_NUM user_report_data_size, PAL_PTR quote,
                        PAL_NUM* quote_size) {
    __UNUSED(user_report_data);
    __UNUSED(user_report_data_size);
    __UNUSED(quote);
    __UNUSED(quote_size);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkSetProtectedFilesKey(PAL_PTR pf_key_hex) {
    __UNUSED(pf_key_hex);
    return -PAL_ERROR_NOTIMPLEMENTED;
}
