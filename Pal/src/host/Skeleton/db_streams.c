/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * db_stream.c
 *
 * This file contains APIs to open, read, write and get attribute of
 * streams.
 */

#include "api.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"

void _DkPrintConsole(const void* buf, int size) {
    /* needs to be implemented */
}

/* _DkStreamUnmap for internal use. Unmap stream at certain memory address.
   The memory is unmapped as a whole.*/
int _DkStreamUnmap(void* addr, uint64_t size) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* _DkSendHandle for internal use. Send a PAL_HANDLE over the given
   process handle. */
int _DkSendHandle(PAL_HANDLE hdl, PAL_HANDLE cargo) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* _DkReceiveHandle for internal use. Receive and return a PAL_HANDLE over the
   given PAL_HANDLE else return negative value. */
int _DkReceiveHandle(PAL_HANDLE hdl, PAL_HANDLE* cargo) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}
