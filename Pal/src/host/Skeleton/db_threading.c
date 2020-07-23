/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * db_threading.c
 *
 * This file contain APIs to create, exit and yield a thread.
 */

#include "api.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"

/* _DkThreadCreate for internal use. Create an internal thread
   inside the current process. The arguments callback and param
   specify the starting function and parameters */
int _DkThreadCreate(PAL_HANDLE* handle, int (*callback)(void*), const void* param) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkThreadDelayExecution(unsigned long* duration) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* PAL call DkThreadYieldExecution. Yield the execution
   of the current thread. */
void _DkThreadYieldExecution(void) {
    /* needs to be implemented */
}

/* _DkThreadExit for internal use: Thread exiting */
noreturn void _DkThreadExit(int* clear_child_tid) {
    /* needs to be implemented */
    while (true) {
        /* nothing */
    }
}

int _DkThreadResume(PAL_HANDLE threadHandle) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

struct handle_ops g_thread_ops = {
    /* nothing */
};
