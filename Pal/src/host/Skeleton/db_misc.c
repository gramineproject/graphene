/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs for miscellaneous use.
 */

#include "api.h"
#include "assert.h"
#include "pal.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"

int _DkSystemTimeQuery(uint64_t* out_usec) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkRandomBitsRead(void* buffer, size_t size) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkSegmentRegisterGet(int reg, void** addr) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkSegmentRegisterSet(int reg, void* addr) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkCpuIdRetrieve(unsigned int leaf, unsigned int subleaf, unsigned int values[4]) {
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
