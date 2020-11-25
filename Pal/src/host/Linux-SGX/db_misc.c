/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs for miscellaneous use.
 */

#include <asm/fcntl.h>
#include <linux/time.h>
#include <stdint.h>

#include "api.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_security.h"
#include "gsgx.h"
#include "sgx_api.h"
#include "sgx_attest.h"
#include "toml.h"

#define TSC_REFINE_INIT_TIMEOUT_USECS 10000000

static uint64_t g_tsc_hz = 0;
static uint64_t g_start_tsc = 0;
static uint64_t g_start_usec = 0;
static PAL_LOCK g_tsc_lock = LOCK_INIT;

/**
 * Initialize the data structures used for date/time emulation using TSC
 */
void init_tsc(void) {
    if (is_tsc_usable()) {
        g_tsc_hz = get_tsc_hz();
    }
}

/* TODO: result comes from the untrusted host, introduce some schielding */
int _DkSystemTimeQuery(uint64_t* out_usec) {
    uint64_t usec = 0;
    uint64_t tsc_usec = 0, tsc_cyc1, tsc_cyc2, tsc_cyc, tsc_diff;
    int ret;

    if (g_tsc_hz > 0) {
        _DkInternalLock(&g_tsc_lock);
        if (g_start_tsc > 0 && g_start_usec > 0) {
            /* calculate the TSC-based time */
            tsc_diff = get_tsc() - g_start_tsc;
            if (tsc_diff < INT64_MAX / 1000000) {
                tsc_usec = g_start_usec + (tsc_diff * 1000000 / g_tsc_hz);
                if (tsc_usec < g_start_usec + TSC_REFINE_INIT_TIMEOUT_USECS) {
                    /* no need to refine yet */
                    usec = tsc_usec;
                }
            }
        }
        _DkInternalUnlock(&g_tsc_lock);

        if (!usec) {
            /* refresh the baseline usec and TSC to contain the drift */
            tsc_cyc1 = get_tsc();
            ret = ocall_gettime(&usec);
            tsc_cyc2 = get_tsc();
            if (!ret) {
                /* the ocall_gettime() is a time consuming operation.   *
                 * it includes EENTER and EEXIT instructions, our best  *
                 * estimation is the timestamp obtained in the middle   *
                 * time point, therefore, the tsc_cyc as baseline will  *
                 * be calibrated precisely in this way.                 */
                tsc_cyc = ((tsc_cyc2 - tsc_cyc1) / 2) + tsc_cyc1;
                _DkInternalLock(&g_tsc_lock);
                /* refresh the baseline data if no other thread updated g_start_tsc */
                if (g_start_tsc < tsc_cyc) {
                    g_start_usec = usec;
                    g_start_tsc = tsc_cyc;
                }
                _DkInternalUnlock(&g_tsc_lock);
            } else {
                return -PAL_ERROR_DENIED;
            }
        }
    } else {
        /* fallback to the slow ocall */
        ret = ocall_gettime(&usec);
        if (ret < 0)
            return -PAL_ERROR_DENIED;
    }
    *out_usec = usec;
    return 0;
}

int _DkInstructionCacheFlush(const void* addr, int size) {
    __UNUSED(addr);
    __UNUSED(size);

    return -PAL_ERROR_NOTIMPLEMENTED;
}

#define CPUID_CACHE_SIZE    64
#define CPUID_CACHE_INVALID ((unsigned int)-1)

static PAL_LOCK g_cpuid_cache_lock = LOCK_INIT;

static struct pal_cpuid {
    unsigned int recently;
    unsigned int leaf, subleaf;
    unsigned int values[4];
} pal_cpuid_cache[CPUID_CACHE_SIZE];

static int pal_cpuid_cache_top      = 0;
static unsigned int pal_cpuid_clock = 0;

static int get_cpuid_from_cache(unsigned int leaf, unsigned int subleaf, unsigned int values[4]) {
    _DkInternalLock(&g_cpuid_cache_lock);

    for (int i = 0; i < pal_cpuid_cache_top; i++)
        if (pal_cpuid_cache[i].leaf == leaf && pal_cpuid_cache[i].subleaf == subleaf) {
            values[0]                   = pal_cpuid_cache[i].values[0];
            values[1]                   = pal_cpuid_cache[i].values[1];
            values[2]                   = pal_cpuid_cache[i].values[2];
            values[3]                   = pal_cpuid_cache[i].values[3];
            pal_cpuid_cache[i].recently = ++pal_cpuid_clock;
            _DkInternalUnlock(&g_cpuid_cache_lock);
            return 0;
        }

    _DkInternalUnlock(&g_cpuid_cache_lock);
    return -PAL_ERROR_DENIED;
}

static void add_cpuid_to_cache(unsigned int leaf, unsigned int subleaf, unsigned int values[4]) {
    struct pal_cpuid* chosen;
    _DkInternalLock(&g_cpuid_cache_lock);

    if (pal_cpuid_cache_top < CPUID_CACHE_SIZE) {
        for (int i = 0; i < pal_cpuid_cache_top; i++)
            if (pal_cpuid_cache[i].leaf == leaf && pal_cpuid_cache[i].subleaf == subleaf) {
                _DkInternalUnlock(&g_cpuid_cache_lock);
                return;
            }

        chosen = &pal_cpuid_cache[pal_cpuid_cache_top++];
    } else {
        unsigned int oldest_clock = pal_cpuid_cache[0].recently;
        chosen                    = &pal_cpuid_cache[0];

        if (pal_cpuid_cache[0].leaf == leaf && pal_cpuid_cache[0].subleaf == subleaf) {
            _DkInternalUnlock(&g_cpuid_cache_lock);
            return;
        }

        for (int i = 1; i < pal_cpuid_cache_top; i++) {
            if (pal_cpuid_cache[i].leaf == leaf && pal_cpuid_cache[i].subleaf == subleaf) {
                _DkInternalUnlock(&g_cpuid_cache_lock);
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

    _DkInternalUnlock(&g_cpuid_cache_lock);
}

static inline uint32_t extension_enabled(uint32_t xfrm, uint32_t bit_idx) {
    uint32_t feature_bit = 1U << bit_idx;
    return xfrm & feature_bit;
}

static __sgx_mem_aligned sgx_report_t report;
static __sgx_mem_aligned sgx_target_info_t target_info;
static __sgx_mem_aligned sgx_report_data_t report_data;

/**
 * Initialize the data structures used for CPUID emulation.
 */
void init_cpuid(void) {
    memset(&report, 0, sizeof(report));
    memset(&target_info, 0, sizeof(target_info));
    memset(&report_data, 0, sizeof(report_data));
    sgx_report(&target_info, &report_data, &report);
}

/**
 * Sanity check untrusted CPUID inputs.
 *
 * The basic idea is that there are only a handful of extensions and we know the size needed to
 * store each extension's state. Use this to sanitize host's untrusted cpuid output. We also know
 * through xfrm what extensions are enabled inside the enclave.
 */
static void sanity_check_cpuid(uint32_t leaf, uint32_t subleaf, uint32_t values[4]) {
    uint64_t xfrm = report.body.attributes.xfrm;

    enum cpu_extension { x87 = 0, SSE, AVX, MPX_1, MPX_2, AVX512_1, AVX512_2, AVX512_3, PKRU = 9 };
    const uint32_t extension_sizes_bytes[] = {
        [AVX] = 256,      [MPX_1] = 64,      [MPX_2] = 64, [AVX512_1] = 64,
        [AVX512_2] = 512, [AVX512_3] = 1024, [PKRU] = 8};
    /* Note that AVX offset is 576 bytes and MPX_1 starts at 960. The AVX state size is 256, leaving
     * 128 bytes unaccounted for. */
    const uint32_t extension_offset_bytes[] = {
        [AVX] = 576,       [MPX_1] = 960,     [MPX_2] = 1024, [AVX512_1] = 1088,
        [AVX512_2] = 1152, [AVX512_3] = 1664, [PKRU] = 2688};
    enum register_index { EAX = 0, EBX, ECX, EDX };

    const uint32_t EXTENDED_STATE_LEAF = 0xd;

    if (leaf == EXTENDED_STATE_LEAF) {
        switch (subleaf) {
            case 0x0:
                /* From the SDM: "EDX:EAX is a bitmap of all the user state components that can be
                 * managed using the XSAVE feature set. A bit can be set in XCR0 if and only if the
                 * corresponding bit is set in this bitmap. Every processor that supports the XSAVE
                 * feature set will set EAX[0] (x87 state) and EAX[1] (SSE state)."
                 *
                 * On EENTER/ERESUME, the system installs xfrm into XCR0. Hence, we return xfrm here
                 * in EAX.
                 */
                values[EAX] = xfrm;

                /* From the SDM: "EBX enumerates the size (in bytes) required by the XSAVE
                 * instruction for an XSAVE area containing all the user state components
                 * corresponding to bits currently set in XCR0."
                 */
                uint32_t xsave_size = 0;
                /* Start from AVX since x87 and SSE are always captured using XSAVE. Also, x87 and
                 * SSE state size is implicitly included in the extension's offset, e.g., AVX's
                 * offset is 576 which includes x87 and SSE state as well as the XSAVE header. */
                for (int i = AVX; i <= PKRU; i++) {
                    if (extension_enabled(xfrm, i)) {
                        xsave_size = extension_offset_bytes[i] + extension_sizes_bytes[i];
                    }
                }
                values[EBX] = xsave_size;

                /* From the SDM: "ECX enumerates the size (in bytes) required by the XSAVE
                 * instruction for an XSAVE area containing all the user state components supported
                 * by this processor."
                 *
                 * We are assuming here that inside the enclave, ECX and EBX for leaf 0xD and
                 * subleaf 0x1 should always be identical, while outside they can potentially be
                 * different. Also, outside of SGX EBX can change at runtime, while ECX is a static
                 * property.
                 */
                values[ECX] = values[EBX];
                values[EDX] = 0;

                break;
            case 0x1: {
                const uint32_t xsave_legacy_size = 512;
                const uint32_t xsave_header = 64;
                uint32_t save_size_bytes = xsave_legacy_size + xsave_header;

                /* Start with AVX, since x87 and SSE state is already included when initializing
                 * `save_size_bytes`. */
                for (int i = AVX; i <= PKRU; i++) {
                    if (extension_enabled(xfrm, i)) {
                        save_size_bytes += extension_sizes_bytes[i];
                    }
                }
                /* EBX reports the actual size occupied by those extensions irrespective of their
                 * offsets within the xsave area.
                 */
                values[EBX] = save_size_bytes;

                break;
            }
            case AVX:
            case MPX_1:
            case MPX_2:
            case AVX512_1:
            case AVX512_2:
            case AVX512_3:
            case PKRU:
                if (extension_enabled(xfrm, subleaf)) {
                    if (values[EAX] != extension_sizes_bytes[subleaf]) {
                        SGX_DBG(DBG_E, "Unexpected value in host CPUID. Exiting...\n");
                        _DkProcessExit(1);
                    }
                } else {
                    if (values[EAX] != 0) {
                        SGX_DBG(DBG_E, "Unexpected value in host CPUID. Exiting...\n");
                        _DkProcessExit(1);
                    }
                }
                break;
        }
    }
}

int _DkCpuIdRetrieve(unsigned int leaf, unsigned int subleaf, unsigned int values[4]) {
    bool skip_cache = false;

    /* the cpu core info cannot be cached due to its data varying depending on the calling thread */
    if (leaf == CPUID_EXT_TOPOLOGY_ENUMERATION_LEAF ||
            leaf == CPUID_V2EXT_TOPOLOGY_ENUMERATION_LEAF) {
        skip_cache = true;
    }

    if (!skip_cache && !get_cpuid_from_cache(leaf, subleaf, values))
        return 0;

    if (IS_ERR(ocall_cpuid(leaf, subleaf, values)))
        return -PAL_ERROR_DENIED;

    sanity_check_cpuid(leaf, subleaf, values);

    if (!skip_cache)
        add_cpuid_to_cache(leaf, subleaf, values);

    return 0;
}

int _DkAttestationReport(PAL_PTR user_report_data, PAL_NUM* user_report_data_size,
                         PAL_PTR target_info, PAL_NUM* target_info_size, PAL_PTR report,
                         PAL_NUM* report_size) {
    __sgx_mem_aligned sgx_report_data_t stack_report_data = {0};
    __sgx_mem_aligned sgx_target_info_t stack_target_info = {0};
    __sgx_mem_aligned sgx_report_t stack_report = {0};

    if (!user_report_data_size || !target_info_size || !report_size)
        return -PAL_ERROR_INVAL;

    if (*user_report_data_size != sizeof(stack_report_data) ||
        *target_info_size != sizeof(stack_target_info) || *report_size != sizeof(stack_report)) {
        /* inform the caller of SGX sizes for user_report_data, target_info, and report */
        goto out;
    }

    if (!user_report_data || !target_info) {
        /* cannot produce report without user_report_data or target_info */
        goto out;
    }

    bool populate_target_info = false;
    if (!memcmp(target_info, &stack_target_info, sizeof(stack_target_info))) {
        /* caller supplied all-zero target_info, wants to get this enclave's target info */
        populate_target_info = true;
    }

    memcpy(&stack_report_data, user_report_data, sizeof(stack_report_data));
    memcpy(&stack_target_info, target_info, sizeof(stack_target_info));

    int ret = sgx_report(&stack_target_info, &stack_report_data, &stack_report);
    if (ret < 0) {
        /* caller already provided reasonable sizes, so just error out without updating them */
        return -PAL_ERROR_INVAL;
    }

    if (populate_target_info) {
        sgx_target_info_t* ti = (sgx_target_info_t*)target_info;
        memcpy(&ti->attributes, &stack_report.body.attributes, sizeof(ti->attributes));
        memcpy(&ti->config_id, &stack_report.body.config_id, sizeof(ti->config_id));
        memcpy(&ti->config_svn, &stack_report.body.config_svn, sizeof(ti->config_svn));
        memcpy(&ti->misc_select, &stack_report.body.misc_select, sizeof(ti->misc_select));
        memcpy(&ti->mr_enclave, &stack_report.body.mr_enclave, sizeof(ti->mr_enclave));
    }

    if (report) {
        /* report may be NULL if caller only wants to know the size of target_info and/or report */
        memcpy(report, &stack_report, sizeof(stack_report));
    }

out:
    *user_report_data_size = sizeof(stack_report_data);
    *target_info_size      = sizeof(stack_target_info);
    *report_size           = sizeof(stack_report);
    return 0;
}

int _DkAttestationQuote(const PAL_PTR user_report_data, PAL_NUM user_report_data_size,
                        PAL_PTR quote, PAL_NUM* quote_size) {
    if (user_report_data_size != sizeof(sgx_report_data_t))
        return -PAL_ERROR_INVAL;

    int ret;
    bool is_epid;
    sgx_spid_t spid;
    bool linkable;

    /* read sgx.ra_client_spid from manifest (must be hex string) */
    char* ra_client_spid_str = NULL;
    ret = toml_string_in(g_pal_state.manifest_root, "sgx.ra_client_spid", &ra_client_spid_str);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Cannot parse \'sgx.ra_client_spid\' "
                       "(the value must be put in double quotes!)\n");
        return -PAL_ERROR_INVAL;
    }

    if (!ra_client_spid_str || strlen(ra_client_spid_str) == 0) {
        /* No Software Provider ID (SPID) specified in the manifest, it is DCAP attestation --
         * for DCAP, spid and linkable arguments are ignored (we unset them for sanity) */
        is_epid = false;
        memset(&spid, 0, sizeof(spid));
        linkable = false;
    } else {
        /* SPID specified in the manifest, it is EPID attestation -- read spid and linkable */
        is_epid = true;

        if (strlen(ra_client_spid_str) != sizeof(sgx_spid_t) * 2) {
            SGX_DBG(DBG_E, "Malformed \'sgx.ra_client_spid\' value in the manifest: %s\n",
                    ra_client_spid_str);
            free(ra_client_spid_str);
            return -PAL_ERROR_INVAL;
        }

        for (size_t i = 0; i < strlen(ra_client_spid_str); i++) {
            int8_t val = hex2dec(ra_client_spid_str[i]);
            if (val < 0) {
                SGX_DBG(DBG_E, "Malformed \'sgx.ra_client_spid\' value in the manifest: %s\n",
                        ra_client_spid_str);
                free(ra_client_spid_str);
                return -PAL_ERROR_INVAL;
            }
            spid[i / 2] = spid[i / 2] * 16 + (uint8_t)val;
        }

        /* read sgx.ra_client_linkable from manifest */
        int64_t linkable_int64;
        ret = toml_int_in(g_pal_state.manifest_root, "sgx.ra_client_linkable",
                          /*defaultval=*/0, &linkable_int64);
        if (ret < 0 || (linkable_int64 != 0 && linkable_int64 != 1)) {
            SGX_DBG(DBG_E, "Cannot parse \'sgx.ra_client_linkable\' (the value must be 0 or 1)\n");
            free(ra_client_spid_str);
            return -PAL_ERROR_INVAL;
        }
        linkable = !!linkable_int64;
    }

    free(ra_client_spid_str);

    sgx_quote_nonce_t nonce;
    ret = _DkRandomBitsRead(&nonce, sizeof(nonce));
    if (ret < 0)
        return ret;

    char* pal_quote       = NULL;
    size_t pal_quote_size = 0;

    ret = sgx_get_quote(is_epid ? &spid : NULL, &nonce, user_report_data, linkable, &pal_quote,
                        &pal_quote_size);
    if (ret < 0)
        return ret;

    if (*quote_size < pal_quote_size) {
        *quote_size = pal_quote_size;
        free(pal_quote);
        return -PAL_ERROR_NOMEM;
    }

    if (quote) {
        /* quote may be NULL if caller only wants to know the size of the quote */
        assert(pal_quote);
        memcpy(quote, pal_quote, pal_quote_size);
    }

    *quote_size = pal_quote_size;
    free(pal_quote);
    return 0;
}

int _DkSetProtectedFilesKey(const PAL_PTR pf_key_hex) {
    return set_protected_files_key(pf_key_hex);
}
