/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs for miscellaneous use.
 */

#include "api.h"
#include "pal.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"

int DkSystemTimeQuery(PAL_NUM* time) {
    assert(current_context_is_libos());
    current_context_set_pal();

    int ret = _DkSystemTimeQuery(time);

    current_context_set_libos();
    return ret;
}

int DkRandomBitsRead(PAL_PTR buffer, PAL_NUM size) {
    assert(current_context_is_libos());
    current_context_set_pal();

    int ret = _DkRandomBitsRead((void*)buffer, size);

    current_context_set_libos();
    return ret;
}

#if defined(__x86_64__)
int DkSegmentRegisterGet(PAL_FLG reg, PAL_PTR* addr) {
    assert(current_context_is_libos());
    current_context_set_pal();

    int ret = _DkSegmentRegisterGet(reg, addr);

    current_context_set_libos();
    return ret;
}

int DkSegmentRegisterSet(PAL_FLG reg, PAL_PTR addr) {
    assert(current_context_is_libos());
    current_context_set_pal();

    int ret = _DkSegmentRegisterSet(reg, addr);

    current_context_set_libos();
    return ret;
}
#endif

PAL_NUM DkMemoryAvailableQuota(void) {
    assert(current_context_is_libos());
    current_context_set_pal();

    long quota = _DkMemoryAvailableQuota();
    if (quota < 0)
        quota = 0;

    PAL_NUM ret = (PAL_NUM)quota;

    current_context_set_libos();
    return ret;
}

int DkCpuIdRetrieve(PAL_IDX leaf, PAL_IDX subleaf, PAL_IDX values[4]) {
    assert(current_context_is_libos());
    current_context_set_pal();

    unsigned int vals[4];
    int ret = _DkCpuIdRetrieve(leaf, subleaf, vals);
    if (ret < 0) {
        current_context_set_libos();
        return ret;
    }

    values[0] = vals[0];
    values[1] = vals[1];
    values[2] = vals[2];
    values[3] = vals[3];

    current_context_set_libos();
    return 0;
}

int DkAttestationReport(PAL_PTR user_report_data, PAL_NUM* user_report_data_size,
                        PAL_PTR target_info, PAL_NUM* target_info_size, PAL_PTR report,
                        PAL_NUM* report_size) {
    assert(current_context_is_libos());
    current_context_set_pal();

    int ret = _DkAttestationReport(user_report_data, user_report_data_size, target_info,
                                   target_info_size, report, report_size);

    current_context_set_libos();
    return ret;
}

int DkAttestationQuote(PAL_PTR user_report_data, PAL_NUM user_report_data_size, PAL_PTR quote,
                       PAL_NUM* quote_size) {
    assert(current_context_is_libos());
    current_context_set_pal();

    int ret = _DkAttestationQuote(user_report_data, user_report_data_size, quote, quote_size);

    current_context_set_libos();
    return ret;
}

int DkSetProtectedFilesKey(PAL_PTR pf_key_hex) {
    assert(current_context_is_libos());
    current_context_set_pal();

    int ret = _DkSetProtectedFilesKey(pf_key_hex);

    current_context_set_libos();
    return ret;
}
