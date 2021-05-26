/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs to create, exit and yield a thread.
 */

#include "api.h"
#include "pal.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"

/* PAL call DkThreadCreate: create a thread inside the current process */
int DkThreadCreate(PAL_PTR addr, PAL_PTR param, PAL_HANDLE* handle) {
    assert(current_context_is_libos());
    current_context_set_pal();

    *handle = NULL;
    int ret = _DkThreadCreate(handle, (int (*)(void*))addr, (const void*)param);

    current_context_set_libos();
    return ret;
}

/* PAL call DkThreadYieldExecution. Yield the execution of the current thread. */
void DkThreadYieldExecution(void) {
    assert(current_context_is_libos());
    current_context_set_pal();

    _DkThreadYieldExecution();

    current_context_set_libos();
}

/* PAL call DkThreadExit: simply exit the current thread no matter what */
noreturn void DkThreadExit(PAL_PTR clear_child_tid) {
    assert(current_context_is_libos());
    current_context_set_pal();

    _DkThreadExit((int*)clear_child_tid);
    /* UNREACHABLE */
}

/* PAL call DkThreadResume: resume the execution of a thread which is delayed before */
int DkThreadResume(PAL_HANDLE threadHandle) {
    assert(current_context_is_libos());
    current_context_set_pal();

    if (!threadHandle || !IS_HANDLE_TYPE(threadHandle, thread)) {
        current_context_set_libos();
        return -PAL_ERROR_INVAL;
    }

    int ret = _DkThreadResume(threadHandle);

    current_context_set_libos();
    return ret;
}

int DkThreadSetCpuAffinity(PAL_HANDLE thread, PAL_NUM cpumask_size, PAL_PTR cpu_mask) {
    assert(current_context_is_libos());
    current_context_set_pal();

    int ret = _DkThreadSetCpuAffinity(thread, cpumask_size, cpu_mask);

    current_context_set_libos();
    return ret;
}

int DkThreadGetCpuAffinity(PAL_HANDLE thread, PAL_NUM cpumask_size, PAL_PTR cpu_mask) {
    assert(current_context_is_libos());
    current_context_set_pal();

    int ret = _DkThreadGetCpuAffinity(thread, cpumask_size, cpu_mask);

    current_context_set_libos();
    return ret;
}
