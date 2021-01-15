/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */
#ifndef _VDSO_SYSCALL_H
#define _VDSO_SYSCALL_H

static inline long arch_syscall(long (*syscalldb)(void), long nr, long arg1, long arg2) {
    long ret;
    __asm__ volatile(
        "lea .Lret%=(%%rip), %%rcx\n"
        "jmp *%[syscalldb]\n"
        ".Lret%=:\n"
        : "=a" (ret)
        : "0" (nr), "D"(arg1), "S"(arg2), [syscalldb] "rm" (syscalldb)
        : "memory", "rcx", "r11"
    );
    return ret;
}

#endif // _VDSO_SYSCALL_H
