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

PAL_NUM DkSystemTimeQuery(void) {
    ENTER_PAL_CALL(DkSystemTimeQuery);
    uint64_t time;
    int ret = _DkSystemTimeQuery(&time);
    if (ret < 0) {
        _DkRaiseFailure(-ret);
        // TODO: Fix this interface to allow returning errors.
        time = 0;
    }
    LEAVE_PAL_CALL_RETURN(time);
}

PAL_NUM DkRandomBitsRead(PAL_PTR buffer, PAL_NUM size) {
    ENTER_PAL_CALL(DkRandomBitsRead);

    int ret = _DkRandomBitsRead((void*)buffer, size);

    LEAVE_PAL_CALL_RETURN(ret);
}

#if defined(__x86_64__)
PAL_BOL DkSegmentRegisterGet(PAL_FLG reg, PAL_PTR* addr) {
    ENTER_PAL_CALL(DkSegmentRegisterGet);

    int ret = _DkSegmentRegisterGet(reg, addr);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    LEAVE_PAL_CALL_RETURN(PAL_TRUE);
}

PAL_BOL DkSegmentRegisterSet(PAL_FLG reg, PAL_PTR addr) {
    ENTER_PAL_CALL(DkSegmentRegisterSet);

    int ret = _DkSegmentRegisterSet(reg, addr);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    LEAVE_PAL_CALL_RETURN(PAL_TRUE);
}
#endif

PAL_BOL DkInstructionCacheFlush(PAL_PTR addr, PAL_NUM size) {
    ENTER_PAL_CALL(DkInstructionCacheFlush);

    if (!addr || !size) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    int ret = _DkInstructionCacheFlush((void*)addr, size);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    LEAVE_PAL_CALL_RETURN(PAL_TRUE);
}

PAL_NUM DkMemoryAvailableQuota(void) {
    ENTER_PAL_CALL(DkMemoryAvailableQuota);

    long quota = _DkMemoryAvailableQuota();
    if (quota < 0)
        quota = 0;

    LEAVE_PAL_CALL_RETURN((PAL_NUM)quota);
}

PAL_BOL
DkCpuIdRetrieve(PAL_IDX leaf, PAL_IDX subleaf, PAL_IDX values[4]) {
    ENTER_PAL_CALL(DkCpuIdRetrieve);

    unsigned int vals[4];
    int ret = _DkCpuIdRetrieve(leaf, subleaf, vals);
    if (ret < 0) {
        _DkRaiseFailure(-ret);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    values[0] = vals[0];
    values[1] = vals[1];
    values[2] = vals[2];
    values[3] = vals[3];

    LEAVE_PAL_CALL_RETURN(PAL_TRUE);
}

PAL_BOL DkAttestationReport(PAL_PTR user_report_data, PAL_NUM* user_report_data_size,
                            PAL_PTR target_info, PAL_NUM* target_info_size, PAL_PTR report,
                            PAL_NUM* report_size) {
    ENTER_PAL_CALL(DkAttestationReport);

    int ret = _DkAttestationReport(user_report_data, user_report_data_size, target_info,
                                   target_info_size, report, report_size);
    if (ret < 0) {
        _DkRaiseFailure(-ret);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }
    LEAVE_PAL_CALL_RETURN(PAL_TRUE);
}

PAL_BOL DkAttestationQuote(PAL_PTR user_report_data, PAL_NUM user_report_data_size, PAL_PTR quote,
                           PAL_NUM* quote_size) {
    ENTER_PAL_CALL(DkAttestationQuote);

    int ret = _DkAttestationQuote(user_report_data, user_report_data_size, quote, quote_size);
    if (ret < 0) {
        _DkRaiseFailure(-ret);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }
    LEAVE_PAL_CALL_RETURN(PAL_TRUE);
}

PAL_BOL DkSetProtectedFilesKey(PAL_PTR pf_key_hex) {
    ENTER_PAL_CALL(DkSetProtectedFilesKey);

    int ret = _DkSetProtectedFilesKey(pf_key_hex);
    if (ret < 0) {
        _DkRaiseFailure(-ret);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }
    LEAVE_PAL_CALL_RETURN(PAL_TRUE);
}
