/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include <asm/prctl.h>

#include "pal.h"
#include "shim_internal.h"
#include "shim_table.h"
#include "shim_tcb.h"

long shim_do_arch_prctl(int code, void* addr) {
    switch (code) {
        case ARCH_SET_FS:
            set_tls((unsigned long)addr);
            return 0;

        case ARCH_GET_FS:
            return pal_to_unix_errno(DkSegmentRegisterGet(PAL_SEGMENT_FS, addr));

        default:
            log_warning("Not supported flag (0x%x) passed to arch_prctl", code);
            return -ENOSYS;
    }
}
