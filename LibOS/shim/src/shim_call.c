/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/* This file implements Graphene custom calls from userspace. See `shim_entry.h` for details. */

#include <linux/errno.h>
#include <limits.h>

#include "api.h"
#include "shim_entry.h"
#include "shim_entry_api.h"

long handle_call(int number, unsigned long arg1, unsigned long arg2, unsigned long arg3,
                 unsigned long arg4) {
    __UNUSED(arg3);
    __UNUSED(arg4);
    switch (number) {
        case SHIM_CALL_REGISTER_LIBRARY:
            return register_library((const char*)arg1, arg2);

        case SHIM_CALL_RUN_TEST:
            return run_test((const char*)arg1);

        default:
            log_warning("handle_call: invalid number: %d", number);
            return -EINVAL;
    }
}

/* Test: do nothing, return success */
static int run_test_pass(void) {
    return 0;
}

/* Test: invoke undefined behavior; enabled only when Graphene is compiled with UBSan */
static int run_test_undefined(void) {
#ifdef UBSAN
    volatile int x = INT_MAX;
    x++;
    return 0;
#else
    return -EINVAL;
#endif
}

int run_test(const char* test_name) {
    int ret;

    log_debug("run_test(\"%s\") = ...", test_name);
    if (strcmp(test_name, "pass") == 0) {
        ret = run_test_pass();
    } else if (strcmp(test_name, "undefined") == 0) {
        ret = run_test_undefined();
    } else {
        ret = -EINVAL;
    }
    log_debug("run_test(\"%s\") = %d", test_name, ret);
    return ret;
}
