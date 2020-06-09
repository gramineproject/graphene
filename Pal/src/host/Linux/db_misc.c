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
    if (linux_state.vdso_clock_gettime) {
        ret = linux_state.vdso_clock_gettime(CLOCK_REALTIME, &time);
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
    if (linux_state.vdso_gettimeofday) {
        ret = linux_state.vdso_gettimeofday(&time, NULL);
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

#if USE_ARCH_RDRAND == 1
int _DkRandomBitsRead(void* buffer, int size) {
    int total_bytes = 0;
    do {
        unsigned long rand;
        asm volatile(".Lretry: rdrand %%rax\r\n jnc .Lretry\r\n" : "=a"(rand)::"memory", "cc");

        if (total_bytes + sizeof(rand) <= size) {
            *(unsigned long*)(buffer + total_bytes) = rand;
            total_bytes += sizeof(rand);
        } else {
            for (int i = 0; i < size - total_bytes; i++)
                *(unsigned char*)(buffer + total_bytes + i) = ((unsigned char*)&rand)[i];
            total_bytes = size;
        }
    } while (total_bytes < size);
    return 0;
}
#else
size_t _DkRandomBitsRead(void* buffer, size_t size) {
    if (!pal_sec.random_device) {
        int fd = INLINE_SYSCALL(open, 3, RANDGEN_DEVICE, O_RDONLY, 0);
        if (IS_ERR(fd))
            return -PAL_ERROR_DENIED;

        pal_sec.random_device = fd;
    }

    size_t total_bytes = 0;
    do {
        int bytes = INLINE_SYSCALL(read, 3, pal_sec.random_device, buffer + total_bytes,
                                   size - total_bytes);
        if (IS_ERR(bytes))
            return -PAL_ERROR_DENIED;

        total_bytes += (size_t)bytes;
    } while (total_bytes < size);

    return 0;
}
#endif

#if defined(__i386__)
#include <asm/ldt.h>
#elif defined(__x86_64__)
#include <asm/prctl.h>
#endif

int _DkSegmentRegisterSet(int reg, const void* addr) {
    int ret = 0;

#if defined(__i386__)
    struct user_desc u_info;

    ret = INLINE_SYSCALL(get_thread_area, 1, &u_info);

    if (IS_ERR(ret))
        return NULL;

    u_info->entry_number = -1;
    u_info->base_addr    = (unsigned int)addr;

    ret = INLINE_SYSCALL(set_thread_area, 1, &u_info);
#elif defined(__x86_64__)
    if (reg == PAL_SEGMENT_FS) {
        ret = INLINE_SYSCALL(arch_prctl, 2, ARCH_SET_FS, addr);
    } else if (reg == PAL_SEGMENT_GS) {
        return -PAL_ERROR_DENIED;
    } else {
        return -PAL_ERROR_INVAL;
    }
#else
#error Unsupported architecture
#endif
    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    return 0;
}

int _DkSegmentRegisterGet(int reg, void** addr) {
    int ret;

#if defined(__i386__)
    struct user_desc u_info;

    ret = INLINE_SYSCALL(get_thread_area, 1, &u_info);

    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    *addr = (void*)u_info->base_addr;
#elif defined(__x86_64__)
    unsigned long ret_addr;

    if (reg == PAL_SEGMENT_FS) {
        ret = INLINE_SYSCALL(arch_prctl, 2, ARCH_GET_FS, &ret_addr);
    } else if (reg == PAL_SEGMENT_GS) {
        // The GS segment is used for the internal TCB of PAL
        return -PAL_ERROR_DENIED;
    } else {
        return -PAL_ERROR_INVAL;
    }

    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    *addr = (void*)ret_addr;
#else
#error Unsupported architecture
#endif
    return 0;
}

int _DkInstructionCacheFlush(const void* addr, int size) {
    __UNUSED(addr);
    __UNUSED(size);

    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkCpuIdRetrieve(unsigned int leaf, unsigned int subleaf, unsigned int values[4]) {
    cpuid(leaf, subleaf, values);
    return 0;
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
