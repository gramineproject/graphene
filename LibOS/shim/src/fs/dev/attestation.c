/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Labs */

/*!
 * \file
 *
 * This file contains the implementation of local- and remote-attestation logic implemented via
 * `/dev/attestation/{user_report_data, target_info, my_target_info, report, quote}` pseudo-files.
 *
 * The attestation logic uses DkAttestationReport() and DkAttestationQuote() and is generic enough
 * to support attestation flows similar to Intel SGX. Currently only SGX attestation is used.
 *
 * This pseudo-FS interface is not thread-safe. It is the responsibility of the application to
 * correctly synchronize concurrent accesses to the pseudo-files. We expect attestation flows to
 * be generally single-threaded and therefore do not introduce synchronization here.
 */

#include "shim_fs.h"
#include "stat.h"

/* user_report_data, target_info and quote are opaque blobs of predefined maximum sizes. Currently
 * these sizes are overapproximations of SGX requirements (report_data is 64B, target_info is
 * 512B, EPID quote is about 1KB, DCAP quote is about 4KB). */
#define USER_REPORT_DATA_MAX_SIZE 256
#define TARGET_INFO_MAX_SIZE      1024
#define QUOTE_MAX_SIZE            8192

static char g_user_report_data[USER_REPORT_DATA_MAX_SIZE] = {0};
static size_t g_user_report_data_size = 0;

static char g_target_info[TARGET_INFO_MAX_SIZE] = {0};
static size_t g_target_info_size = 0;

static size_t g_report_size = 0;

#define PF_KEY_HEX_SIZE (32 + 1)
static char g_pf_key_hex[PF_KEY_HEX_SIZE] = {0};

static int init_attestation_struct_sizes(void) {
    if (g_user_report_data_size && g_target_info_size && g_report_size) {
        /* already initialized, nothing to do here */
        return 0;
    }

    bool ok = DkAttestationReport(/*user_report_data=*/NULL, &g_user_report_data_size,
                                  /*target_info=*/NULL, &g_target_info_size,
                                  /*report=*/NULL, &g_report_size);
    if (!ok)
        return -EACCES;

    assert(g_user_report_data_size && g_user_report_data_size <= sizeof(g_user_report_data));
    assert(g_target_info_size && g_target_info_size <= sizeof(g_target_info));
    assert(g_report_size);
    return 0;
}

static int dev_attestation_readonly_mode(const char* name, mode_t* mode) {
    __UNUSED(name);
    *mode = FILE_R_MODE | S_IFREG;
    return 0;
}

static int dev_attestation_readwrite_mode(const char* name, mode_t* mode) {
    __UNUSED(name);
    *mode = FILE_RW_MODE | S_IFREG;
    return 0;
}

static int dev_attestation_readonly_stat(const char* name, struct stat* buf) {
    __UNUSED(name);
    memset(buf, 0, sizeof(*buf));
    buf->st_dev  = 1; /* dummy ID of device containing file */
    buf->st_ino  = 1; /* dummy inode number */
    buf->st_mode = FILE_R_MODE | S_IFREG;
    return 0;
}

static int dev_attestation_readwrite_stat(const char* name, struct stat* buf) {
    __UNUSED(name);
    memset(buf, 0, sizeof(*buf));
    buf->st_dev  = 1; /* dummy ID of device containing file */
    buf->st_ino  = 1; /* dummy inode number */
    buf->st_mode = FILE_RW_MODE | S_IFREG;
    return 0;
}

/* callback for str FS; copies contents of `/dev/attestation/user_report_data` file in the
 * global `g_user_report_data` struct on file close */
static int user_report_data_modify(struct shim_handle* hdl) {
    assert(g_user_report_data_size);
    memcpy(&g_user_report_data, hdl->info.str.data->str, g_user_report_data_size);
    return 0;
}

/* callback for str FS; copies contents of `/dev/attestation/target_info` file in the global
 * `g_target_info` struct on file close */
static int target_info_modify(struct shim_handle* hdl) {
    assert(g_target_info_size);
    memcpy(&g_target_info, hdl->info.str.data->str, g_target_info_size);
    return 0;
}

/*!
 * \brief Modify/obtain user-defined report data used in `report` and `quote` pseudo-files.
 *
 * This file `/dev/attestation/user_report_data` can be opened for read and write. Typically, it is
 * opened and written into before opening and reading from `/dev/attestation/report` or
 * `/dev/attestation/quote` files, so they can use the user-provided report data blob.
 *
 * In case of SGX, user report data can be an arbitrary string of size 64B.
 */
static int dev_attestation_user_report_data_open(struct shim_handle* hdl, const char* name,
                                                 int flags) {
    __UNUSED(name);
    __UNUSED(flags);

    if (strcmp(PAL_CB(host_type), "Linux-SGX")) {
        /* this pseudo-file is only available with Linux-SGX */
        return -EACCES;
    }

    if (init_attestation_struct_sizes() < 0)
        return -EACCES;

    struct shim_str_data* data = calloc(1, sizeof(*data));
    if (!data)
        return -ENOMEM;

    char* data_str_userreportdata = calloc(1, g_user_report_data_size);
    if (!data_str_userreportdata) {
        free(data);
        return -ENOMEM;
    }

    memcpy(data_str_userreportdata, &g_user_report_data, g_user_report_data_size);

    data->str      = data_str_userreportdata;
    data->buf_size = g_user_report_data_size;
    data->modify   = &user_report_data_modify; /* invoked when file is closed */

    hdl->type          = TYPE_STR;
    hdl->acc_mode      = MAY_WRITE | MAY_READ;
    hdl->info.str.data = data;
    hdl->info.str.ptr  = data_str_userreportdata;
    return 0;
}

/*!
 * \brief Modify/obtain target info used in `report` and `quote` pseudo-files.
 *
 * This file `/dev/attestation/target_info` can be opened for read and write. Typically, it is
 * opened and written into before opening and reading from `/dev/attestation/report` or
 * `/dev/attestation/quote` files, so they can use the provided target info.
 *
 * In case of SGX, target info is an opaque blob of size 512B.
 */
static int dev_attestation_target_info_open(struct shim_handle* hdl, const char* name, int flags) {
    __UNUSED(name);
    __UNUSED(flags);

    if (strcmp(PAL_CB(host_type), "Linux-SGX")) {
        /* this pseudo-file is only available with Linux-SGX */
        return -EACCES;
    }

    if (init_attestation_struct_sizes() < 0)
        return -EACCES;

    struct shim_str_data* data = calloc(1, sizeof(*data));
    if (!data)
        return -ENOMEM;

    char* data_str_ti = calloc(1, g_target_info_size);
    if (!data_str_ti) {
        free(data);
        return -ENOMEM;
    }

    memcpy(data_str_ti, &g_target_info, g_target_info_size);

    data->str      = data_str_ti;
    data->buf_size = g_target_info_size;
    data->modify   = &target_info_modify; /* invoked when file is closed */

    hdl->type          = TYPE_STR;
    hdl->acc_mode      = MAY_WRITE | MAY_READ;
    hdl->info.str.data = data;
    hdl->info.str.ptr  = data_str_ti;
    return 0;
}

/*!
 * \brief Obtain this enclave's target info via DkAttestationReport().
 *
 * This file `/dev/attestation/my_target_info` can be opened for read and will contain the
 * target info of this enclave. The resulting target info blob can be passed to another enclave
 * as part of the local attestation flow.
 *
 * In case of SGX, target info is an opaque blob of size 512B.
 */
static int dev_attestation_my_target_info_open(struct shim_handle* hdl, const char* name,
                                               int flags) {
    __UNUSED(name);
    int ret;

    char* user_report_data     = NULL;
    char* target_info          = NULL;
    struct shim_str_data* data = NULL;

    if (strcmp(PAL_CB(host_type), "Linux-SGX")) {
        /* this pseudo-file is only available with Linux-SGX */
        return -EACCES;
    }

    if (init_attestation_struct_sizes() < 0)
        return -EACCES;

    if (flags & (O_WRONLY | O_RDWR))
        return -EACCES;

    size_t user_report_data_size = g_user_report_data_size;
    size_t target_info_size      = g_target_info_size;
    size_t report_size           = g_report_size;

    user_report_data = calloc(1, user_report_data_size);
    if (!user_report_data) {
        ret = -ENOMEM;
        goto out;
    }

    target_info = calloc(1, target_info_size);
    if (!target_info) {
        ret = -ENOMEM;
        goto out;
    }

    /* below invocation returns this enclave's target info because we zeroed out (via calloc)
     * target_info: it's a hint to function to update target_info with this enclave's info */
    bool ok = DkAttestationReport(user_report_data, &user_report_data_size, target_info,
                                  &target_info_size, /*report=*/NULL, &report_size);
    if (!ok) {
        ret = -EACCES;
        goto out;
    }

    /* sanity checks: returned struct sizes must be the same as previously obtained ones */
    assert(user_report_data_size == g_user_report_data_size);
    assert(target_info_size == g_target_info_size);
    assert(report_size == g_report_size);

    data = calloc(1, sizeof(*data));
    if (!data) {
        ret = -ENOMEM;
        goto out;
    }

    data->str      = target_info;
    data->buf_size = target_info_size;
    data->len      = target_info_size;

    hdl->type          = TYPE_STR;
    hdl->acc_mode      = MAY_READ;
    hdl->info.str.data = data;
    hdl->info.str.ptr  = target_info;

    ret = 0;
out:
    if (ret < 0) {
        free(target_info);
        free(data);
    }
    free(user_report_data);
    return ret;
}

/*!
 * \brief Obtain report via DkAttestationReport() with previously populated user_report_data
 *        and target_info.
 *
 * Before opening `/dev/attestation/report` for read, user_report_data must be written into
 * `/dev/attestation/user_report_data` and target info must be written into
 * `/dev/attestation/target_info`. Otherwise the obtained report will contain incorrect or
 * stale user_report_data and target_info.
 *
 * In case of SGX, report is a locally obtained EREPORT struct of size 432B.
 */
static int dev_attestation_report_open(struct shim_handle* hdl, const char* name, int flags) {
    __UNUSED(name);
    int ret;

    char* report               = NULL;
    struct shim_str_data* data = NULL;
    char* data_str_report      = NULL;

    if (strcmp(PAL_CB(host_type), "Linux-SGX")) {
        /* this pseudo-file is only available with Linux-SGX */
        return -EACCES;
    }

    if (!g_target_info_size || !g_user_report_data_size || !g_report_size)
        return -EACCES;

    if (flags & (O_WRONLY | O_RDWR))
        return -EACCES;

    report = calloc(1, g_report_size);
    if (!report) {
        ret = -ENOMEM;
        goto out;
    }

    bool ok = DkAttestationReport(&g_user_report_data, &g_user_report_data_size, &g_target_info,
                                  &g_target_info_size, report, &g_report_size);
    if (!ok) {
        ret = -EACCES;
        goto out;
    }

    data = calloc(1, sizeof(*data));
    if (!data) {
        ret = -ENOMEM;
        goto out;
    }

    data_str_report = calloc(1, g_report_size);
    if (!data_str_report) {
        ret = -ENOMEM;
        goto out;
    }

    memcpy(data_str_report, report, g_report_size);

    data->str      = data_str_report;
    data->buf_size = g_report_size;
    data->len      = g_report_size;

    hdl->type          = TYPE_STR;
    hdl->acc_mode      = MAY_READ;
    hdl->info.str.data = data;
    hdl->info.str.ptr  = data_str_report;

    ret = 0;
out:
    if (ret < 0) {
        free(data_str_report);
        free(data);
    }
    free(report);
    return ret;
}

/*!
 * \brief Obtain quote by communicating with the outside-of-enclave service.
 *
 * Before opening `/dev/attestation/quote` for read, user_report_data must be written into
 * `/dev/attestation/user_report_data`. Otherwise the obtained quote will contain incorrect or
 * stale user_report_data. The resulting quote can be passed to another enclave or service as
 * part of the remote attestation flow.
 *
 * Note that this file doesn't depend on contents of files `/dev/attestation/target_info` and
 * `/dev/attestation/my_target_info`. This is because the quote always embeds target info of
 * the current enclave.
 *
 * In case of SGX, the obtained quote is the SGX quote created by the Quoting Enclave.
 */
static int dev_attestation_quote_open(struct shim_handle* hdl, const char* name, int flags) {
    __UNUSED(name);
    int ret;

    uint8_t* quote             = NULL;
    char* data_str_quote       = NULL;
    struct shim_str_data* data = NULL;

    if (strcmp(PAL_CB(host_type), "Linux-SGX")) {
        /* this pseudo-file is only available with Linux-SGX */
        return -EACCES;
    }

    if (!g_user_report_data_size)
        return -EACCES;

    if (flags & (O_WRONLY | O_RDWR))
        return -EACCES;

    size_t quote_size = QUOTE_MAX_SIZE;
    quote = calloc(1, quote_size);
    if (!quote) {
        ret = -ENOMEM;
        goto out;
    }

    bool ok = DkAttestationQuote(&g_user_report_data, g_user_report_data_size, quote, &quote_size);
    if (!ok) {
        ret = -EACCES;
        goto out;
    }

    data = calloc(1, sizeof(*data));
    if (!data) {
        ret = -ENOMEM;
        goto out;
    }

    data_str_quote = calloc(1, quote_size);
    if (!data_str_quote) {
        ret = -ENOMEM;
        goto out;
    }

    memcpy(data_str_quote, quote, quote_size);

    data->str      = data_str_quote;
    data->buf_size = quote_size;
    data->len      = quote_size;

    hdl->type          = TYPE_STR;
    hdl->acc_mode      = MAY_READ;
    hdl->info.str.data = data;
    hdl->info.str.ptr  = data_str_quote;

    ret = 0;
out:
    if (ret < 0) {
        free(data_str_quote);
        free(data);
    }
    free(quote);
    return ret;
}

/* callback for str FS; copies contents of `/dev/attestation/protected_files_key` file in the
 * global `g_pf_key_hex` string on file close and applies new PF key */
static int pfkey_modify(struct shim_handle* hdl) {
    memcpy(&g_pf_key_hex, hdl->info.str.data->str, sizeof(g_pf_key_hex));
    g_pf_key_hex[sizeof(g_pf_key_hex) - 1] = '\0';

    bool ok = DkSetProtectedFilesKey(&g_pf_key_hex);
    return ok ? 0 : -EACCES;
}

/*!
 * \brief Set new wrap key (master key) for protected files.
 *
 * This file must be open for write after successful remote attestation and secret provisioning.
 * Typically, the remote user/service provisions the PF key as part of remote attestation before
 * the user application starts running. The PF key is applied when this file is closed.
 *
 * The PF key must be a 32-char null-terminated AES-GCM encryption key in hex format.
 */
static int dev_attestation_pfkey_open(struct shim_handle* hdl, const char* name, int flags) {
    __UNUSED(name);
    __UNUSED(flags);

    if (strcmp(PAL_CB(host_type), "Linux-SGX")) {
        /* this pseudo-file is only available with Linux-SGX */
        return -EACCES;
    }

    struct shim_str_data* data = calloc(1, sizeof(*data));
    if (!data)
        return -ENOMEM;

    char* data_str_pfkey = calloc(1, sizeof(g_pf_key_hex));
    if (!data_str_pfkey) {
        free(data);
        return -ENOMEM;
    }

    memcpy(data_str_pfkey, &g_pf_key_hex, sizeof(g_pf_key_hex));

    data->str      = data_str_pfkey;
    data->buf_size = sizeof(g_pf_key_hex);
    data->modify   = &pfkey_modify; /* invoked when file is closed */

    hdl->type          = TYPE_STR;
    hdl->acc_mode      = MAY_WRITE | MAY_READ;
    hdl->info.str.data = data;
    hdl->info.str.ptr  = data_str_pfkey;
    return 0;
}

static struct pseudo_fs_ops dev_attestation_user_report_data_fs_ops = {
    .open = &dev_attestation_user_report_data_open,
    .mode = &dev_attestation_readwrite_mode,
    .stat = &dev_attestation_readwrite_stat,
};

static struct pseudo_fs_ops dev_attestation_target_info_fs_ops = {
    .open = &dev_attestation_target_info_open,
    .mode = &dev_attestation_readwrite_mode,
    .stat = &dev_attestation_readwrite_stat,
};

static struct pseudo_fs_ops dev_attestation_my_target_info_fs_ops = {
    .open = &dev_attestation_my_target_info_open,
    .mode = &dev_attestation_readonly_mode,
    .stat = &dev_attestation_readonly_stat,
};

static struct pseudo_fs_ops dev_attestation_report_fs_ops = {
    .open = &dev_attestation_report_open,
    .mode = &dev_attestation_readonly_mode,
    .stat = &dev_attestation_readonly_stat,
};

static struct pseudo_fs_ops dev_attestation_quote_fs_ops = {
    .open = &dev_attestation_quote_open,
    .mode = &dev_attestation_readonly_mode,
    .stat = &dev_attestation_readonly_stat,
};

static struct pseudo_fs_ops dev_attestation_pfkey_fs_ops = {
    .open = &dev_attestation_pfkey_open,
    .mode = &dev_attestation_readwrite_mode,
    .stat = &dev_attestation_readwrite_stat,
};

struct pseudo_fs_ops dev_attestation_fs_ops = {
    .open = &pseudo_dir_open,
    .mode = &pseudo_dir_mode,
    .stat = &pseudo_dir_stat,
};

struct pseudo_dir dev_attestation_dir = {
    .size = 6,
    .ent  = {
        {.name   = "user_report_data",
         .fs_ops = &dev_attestation_user_report_data_fs_ops,
         .type   = LINUX_DT_REG},
        {.name   = "target_info",
         .fs_ops = &dev_attestation_target_info_fs_ops,
         .type   = LINUX_DT_REG},
        {.name   = "my_target_info",
         .fs_ops = &dev_attestation_my_target_info_fs_ops,
         .type   = LINUX_DT_REG},
        {.name = "report",
         .fs_ops = &dev_attestation_report_fs_ops,
         .type = LINUX_DT_REG},
        {.name = "quote",
         .fs_ops = &dev_attestation_quote_fs_ops,
         .type = LINUX_DT_REG},
        {.name   = "protected_files_key",
         .fs_ops = &dev_attestation_pfkey_fs_ops,
         .type   = LINUX_DT_REG},
    }};
