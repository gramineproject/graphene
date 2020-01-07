/* Copyright (C) 2014 Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * db_misc.c
 *
 * This file contains APIs for miscellaneous use.
 */

#include <asm/fcntl.h>
#include <linux/time.h>

#include "api.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_security.h"

#include "sgx_attest.h"

unsigned long _DkSystemTimeQuery(void) {
    unsigned long microsec;
    int ret = ocall_gettime(&microsec);
    if (ret)
        return -PAL_ERROR_DENIED;
    return microsec;
}

size_t _DkRandomBitsRead(void* buffer, size_t size) {
    uint32_t rand;
    for (size_t i = 0; i < size; i += sizeof(rand)) {
        rand = rdrand();
        memcpy(buffer + i, &rand, MIN(sizeof(rand), size - i));
    }
    return 0;
}

int _DkInstructionCacheFlush(const void* addr, int size) {
    __UNUSED(addr);
    __UNUSED(size);

    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkSegmentRegisterSet(int reg, const void* addr) {
    /* GS is internally used, denied any access to it */
    if (reg != PAL_SEGMENT_FS)
        return -PAL_ERROR_DENIED;

    SET_ENCLAVE_TLS(fsbase, (void*)addr);
    wrfsbase((uint64_t)addr);
    return 0;
}

int _DkSegmentRegisterGet(int reg, void** addr) {
    /* GS is internally used, denied any access to it */
    if (reg != PAL_SEGMENT_FS)
        return -PAL_ERROR_DENIED;

    *addr = (void*)GET_ENCLAVE_TLS(fsbase);
    return 0;
}

#define CPUID_CACHE_SIZE    64
#define CPUID_CACHE_INVALID ((unsigned int)-1)

static PAL_LOCK cpuid_cache_lock = LOCK_INIT;

static struct pal_cpuid {
    unsigned int recently;
    unsigned int leaf, subleaf;
    unsigned int values[4];
} pal_cpuid_cache[CPUID_CACHE_SIZE];

static int pal_cpuid_cache_top      = 0;
static unsigned int pal_cpuid_clock = 0;

int get_cpuid_from_cache(unsigned int leaf, unsigned int subleaf, unsigned int values[4]) {
    _DkInternalLock(&cpuid_cache_lock);

    for (int i = 0; i < pal_cpuid_cache_top; i++)
        if (pal_cpuid_cache[i].leaf == leaf && pal_cpuid_cache[i].subleaf == subleaf) {
            values[0]                   = pal_cpuid_cache[i].values[0];
            values[1]                   = pal_cpuid_cache[i].values[1];
            values[2]                   = pal_cpuid_cache[i].values[2];
            values[3]                   = pal_cpuid_cache[i].values[3];
            pal_cpuid_cache[i].recently = ++pal_cpuid_clock;
            _DkInternalUnlock(&cpuid_cache_lock);
            return 0;
        }

    _DkInternalUnlock(&cpuid_cache_lock);
    return -PAL_ERROR_DENIED;
}

void add_cpuid_to_cache(unsigned int leaf, unsigned int subleaf, unsigned int values[4]) {
    struct pal_cpuid* chosen;
    _DkInternalLock(&cpuid_cache_lock);

    if (pal_cpuid_cache_top < CPUID_CACHE_SIZE) {
        for (int i = 0; i < pal_cpuid_cache_top; i++)
            if (pal_cpuid_cache[i].leaf == leaf && pal_cpuid_cache[i].subleaf == subleaf) {
                _DkInternalUnlock(&cpuid_cache_lock);
                return;
            }

        chosen = &pal_cpuid_cache[pal_cpuid_cache_top++];
    } else {
        unsigned int oldest_clock = pal_cpuid_cache[0].recently;
        chosen                    = &pal_cpuid_cache[0];

        if (pal_cpuid_cache[0].leaf == leaf && pal_cpuid_cache[0].subleaf == subleaf) {
            _DkInternalUnlock(&cpuid_cache_lock);
            return;
        }

        for (int i = 1; i < pal_cpuid_cache_top; i++) {
            if (pal_cpuid_cache[i].leaf == leaf && pal_cpuid_cache[i].subleaf == subleaf) {
                _DkInternalUnlock(&cpuid_cache_lock);
                return;
            }

            if (pal_cpuid_cache[i].recently > oldest_clock) {
                chosen       = &pal_cpuid_cache[i];
                oldest_clock = pal_cpuid_cache[i].recently;
            }
        }
    }

    chosen->leaf      = leaf;
    chosen->subleaf   = subleaf;
    chosen->values[0] = values[0];
    chosen->values[1] = values[1];
    chosen->values[2] = values[2];
    chosen->values[3] = values[3];
    chosen->recently  = ++pal_cpuid_clock;

    _DkInternalUnlock(&cpuid_cache_lock);
}

int _DkCpuIdRetrieve(unsigned int leaf, unsigned int subleaf, unsigned int values[4]) {
    if (leaf != 0x4 && leaf != 0x7 && leaf != 0xb)
        subleaf = 0;

    if (!get_cpuid_from_cache(leaf, subleaf, values))
        return 0;

    if (IS_ERR(ocall_cpuid(leaf, subleaf, values)))
        return -PAL_ERROR_DENIED;

    add_cpuid_to_cache(leaf, subleaf, values);
    return 0;
}

PAL_BOL
_DkIASReport (PAL_PTR report, PAL_NUM maxsize, PAL_NUM* size) {

    char spid_hex[sizeof(sgx_spid_t) * 2 + 1];
    ssize_t len = get_config(pal_state.root_config, "sgx.ra_client_spid", spid_hex,
                             sizeof(spid_hex));
    if (len <= 0) {
        SGX_DBG(DBG_E, "*** No client info specified in the manifest. "
                "Graphene will not perform remote attestation ***\n");
        return 0;
    }

    if (len != sizeof(sgx_spid_t) * 2) {
        SGX_DBG(DBG_E, "Malformed sgx.ra_client_spid value in the manifest: %s\n", spid_hex);
        return -PAL_ERROR_INVAL;
    }

    sgx_spid_t spid;
    for (ssize_t i = 0; i < len; i++) {
        int8_t val = hex2dec(spid_hex[i]);
        if (val < 0) {
            SGX_DBG(DBG_E, "Malformed sgx.ra_client_spid value in the manifest: %s\n", spid_hex);
            return -PAL_ERROR_INVAL;
        }
        spid[i/2] = spid[i/2] * 16 + (uint8_t)val;
    }

    char subkey[CONFIG_MAX];
    len = get_config(pal_state.root_config, "sgx.ra_client_key", subkey, sizeof(subkey));
    if (len <= 0) {
        SGX_DBG(DBG_E, "No sgx.ra_client_key in the manifest\n");
        return -PAL_ERROR_INVAL;
    }

    char buf[2];
    len = get_config(pal_state.root_config, "sgx.ra_client_linkable", buf, sizeof(buf));
    bool linkable = (len == 1 && buf[0] == '1');

    len = get_config(pal_state.root_config, "sgx.ra_accept_group_out_of_date", buf, sizeof(buf));
    bool accept_group_out_of_date = (len == 1 && buf[0] == '1');

    len = get_config(pal_state.root_config, "sgx.ra_accept_configuration_needed", buf, sizeof(buf));
    bool accept_configuration_needed = (len == 1 && buf[0] == '1');

    sgx_quote_nonce_t nonce;
    int ret = _DkRandomBitsRead(&nonce, sizeof(nonce));
    if (ret < 0)
        return ret;

    char* status;
    char* timestamp;
    sgx_attestation_t attn;
    __sgx_mem_aligned sgx_report_data_t report_data = {0, };
    ret = sgx_verify_platform(&spid, subkey, &nonce, &report_data, linkable,
                              accept_group_out_of_date, accept_configuration_needed,
                              &attn, &status, &timestamp);
    if (ret < 0)
        return ret;

    if (maxsize >= attn.ias_report_len) {
        memcpy(report, attn.ias_report, attn.ias_report_len);
        *size = attn.ias_report_len;
    }
    return 0;
}
