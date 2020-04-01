/* Copyright (C) 2020 Intel Labs
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

/*!
 * \file
 *
 * This file contains the implementation of local- and remote-attestation logic implemented via
 * `/dev/attestation/{report_data, target_info, my_target_info, report, quote}` pseudo-files.
 */

#include "shim_fs.h"
#include "shim_attestation.h"

static __sgx_mem_aligned sgx_target_info_t g_target_info = {0};
static __sgx_mem_aligned sgx_report_data_t g_report_data = {0};

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
    buf->st_dev  = 1;    /* dummy ID of device containing file */
    buf->st_ino  = 1;    /* dummy inode number */
    buf->st_mode = FILE_R_MODE | S_IFREG;
    return 0;
}

static int dev_attestation_readwrite_stat(const char* name, struct stat* buf) {
    __UNUSED(name);
    memset(buf, 0, sizeof(*buf));
    buf->st_dev  = 1;    /* dummy ID of device containing file */
    buf->st_ino  = 1;    /* dummy inode number */
    buf->st_mode = FILE_RW_MODE | S_IFREG;
    return 0;
}

/* callback for str FS; copies contents of `/dev/attestation/report_data` file in the global
 * `g_report_data` struct on file close */
static int report_data_modify(struct shim_handle* hdl) {
    __UNUSED(hdl);
    memcpy(&g_report_data, hdl->info.str.data->str, sizeof(g_report_data));
    return 0;
}

/* callback for str FS; copies contents of `/dev/attestation/target_info` file in the global
 * `g_target_info` struct on file close */
static int target_info_modify(struct shim_handle* hdl) {
    __UNUSED(hdl);
    memcpy(&g_target_info, hdl->info.str.data->str, sizeof(g_target_info));
    return 0;
}

/*!
 * \brief Modify/obtain SGX report data used in `report` and `quote` pseudo-files.
 *
 * This file `/dev/attestation/report_data` can be opened for read and write. Typically, it is
 * opened and written into before opening and reading from `/dev/attestation/report` or
 * `/dev/attestation/quote` files, so they can use the provided report data blob.
 *
 * SGX report data can be an arbitrary string of size 64B.
 */
static int dev_attestation_report_data_open(struct shim_handle* hdl, const char* name, int flags) {
    __UNUSED(name);
    __UNUSED(flags);

    if (strcmp_static(PAL_CB(host_type), "Linux-SGX")) {
        /* this pseudo-file is only available with Linux-SGX */
        return -EACCES;
    }

    struct shim_str_data* data = calloc(1, sizeof(*data));
    if (!data)
        return -ENOMEM;

    sgx_report_data_t* data_str_reportdata = calloc(1, sizeof(*data_str_reportdata));
    if (!data_str_reportdata) {
        free(data);
        return -ENOMEM;
    }

    memcpy(data_str_reportdata, &g_report_data, sizeof(*data_str_reportdata));

    data->str      = (char*)data_str_reportdata;
    data->buf_size = sizeof(*data_str_reportdata);
    data->modify   = &report_data_modify; /* invoked when file is closed */

    hdl->type          = TYPE_STR;
    hdl->acc_mode      = MAY_WRITE | MAY_READ;
    hdl->info.str.data = data;
    hdl->info.str.ptr  = (char*)data_str_reportdata;
    return 0;
}

/*!
 * \brief Modify/obtain SGX target info used in `report` and `quote` pseudo-files.
 *
 * This file `/dev/attestation/target_info` can be opened for read and write. Typically, it is
 * opened and written into before opening and reading from `/dev/attestation/report` or
 * `/dev/attestation/quote` files, so they can use the provided target info.
 */
static int dev_attestation_target_info_open(struct shim_handle* hdl, const char* name, int flags) {
    __UNUSED(name);
    __UNUSED(flags);

    if (strcmp_static(PAL_CB(host_type), "Linux-SGX")) {
        /* this pseudo-file is only available with Linux-SGX */
        return -EACCES;
    }

    struct shim_str_data* data = calloc(1, sizeof(*data));
    if (!data)
        return -ENOMEM;

    sgx_target_info_t* data_str_ti = calloc(1, sizeof(*data_str_ti));
    if (!data_str_ti) {
        free(data);
        return -ENOMEM;
    }

    memcpy(data_str_ti, &g_target_info, sizeof(*data_str_ti));

    data->str      = (char*)data_str_ti;
    data->buf_size = sizeof(*data_str_ti);
    data->modify   = &target_info_modify; /* invoked when file is closed */

    hdl->type          = TYPE_STR;
    hdl->acc_mode      = MAY_WRITE | MAY_READ;
    hdl->info.str.data = data;
    hdl->info.str.ptr  = (char*)data_str_ti;
    return 0;
}

/*!
 * \brief Obtain this enclave's SGX target info via EREPORT.
 *
 * This file `/dev/attestation/my_target_info` can be opened for read and will contain the SGX
 * target info (sgx_target_info_t struct) of this enclave. The resulting target info struct can
 * be passed to another enclave as part of the local attestation flow.
 */
static int dev_attestation_my_target_info_open(struct shim_handle* hdl, const char* name, int flags) {
    __UNUSED(name);

    if (strcmp_static(PAL_CB(host_type), "Linux-SGX")) {
        /* this pseudo-file is only available with Linux-SGX */
        return -EACCES;
    }

    if (flags & (O_WRONLY | O_RDWR))
        return -EACCES;

    __sgx_mem_aligned sgx_target_info_t target_info = {0};
    __sgx_mem_aligned sgx_report_data_t report_data = {0};
    __sgx_mem_aligned sgx_report_t report;
    int ret = sgx_report(&target_info, &report_data, &report);
    if (ret < 0)
        return ret;

    struct shim_str_data* data = calloc(1, sizeof(*data));
    if (!data)
        return -ENOMEM;

    sgx_target_info_t* data_str_ti = calloc(1, sizeof(*data_str_ti));
    if (!data_str_ti) {
        free(data);
        return -ENOMEM;
    }

    memcpy(&data_str_ti->attributes, &report.body.attributes, sizeof(data_str_ti->attributes));
    memcpy(&data_str_ti->config_id, &report.body.config_id, sizeof(data_str_ti->config_id));
    memcpy(&data_str_ti->config_svn, &report.body.config_svn, sizeof(data_str_ti->config_svn));
    memcpy(&data_str_ti->misc_select, &report.body.misc_select, sizeof(data_str_ti->misc_select));
    memcpy(&data_str_ti->mr_enclave, &report.body.mr_enclave, sizeof(data_str_ti->mr_enclave));

    data->str       = (char*)data_str_ti;
    data->buf_size  = sizeof(*data_str_ti);
    data->len       = sizeof(*data_str_ti);

    hdl->type          = TYPE_STR;
    hdl->acc_mode      = MAY_READ;
    hdl->info.str.data = data;
    hdl->info.str.ptr  = (char*)data_str_ti;
    return 0;
}

/*!
 * \brief Obtain SGX report via EREPORT with previously populated report_data and target_info.
 *
 * Before opening `/dev/attestation/report` for read, report_data blob must be written into
 * `/dev/attestation/report_data` and target info (sgx_target_info_t) must be written into
 * `/dev/attestation/target_info`. Otherwise the obtained SGX report will contain incorrect or
 * stale report_data and target_info.
 */
static int dev_attestation_report_open(struct shim_handle* hdl, const char* name, int flags) {
    __UNUSED(name);

    if (strcmp_static(PAL_CB(host_type), "Linux-SGX")) {
        /* this pseudo-file is only available with Linux-SGX */
        return -EACCES;
    }

    if (flags & (O_WRONLY | O_RDWR))
        return -EACCES;

    __sgx_mem_aligned sgx_report_t report;
    int ret = sgx_report(&g_target_info, &g_report_data, &report);
    if (ret < 0)
        return -EACCES;


    struct shim_str_data* data = calloc(1, sizeof(*data));
    if (!data)
        return -ENOMEM;

    sgx_report_t* data_str_report = calloc(1, sizeof(*data_str_report));
    if (!data_str_report) {
        free(data);
        return -ENOMEM;
    }

    memcpy(data_str_report, &report, sizeof(report));

    data->str      = (char*)data_str_report;
    data->buf_size = sizeof(*data_str_report);
    data->len      = sizeof(*data_str_report);

    hdl->type          = TYPE_STR;
    hdl->acc_mode      = MAY_READ;
    hdl->info.str.data = data;
    hdl->info.str.ptr  = (char*)data_str_report;
    return 0;
}

/*!
 * \brief Obtain SGX quote by communicating with the outside-of-enclave service (Quoting Enclave).
 *
 * Before opening `/dev/attestation/quote` for read, report_data blob must be written into
 * `/dev/attestation/report_data`. Otherwise the obtained SGX report will contain incorrect or
 * stale report_data. The resulting SGX quote can be passed to another enclave or service as
 * part of the remote attestation flow.
 *
 * Note that this file doesn't depend on contents of files `/dev/attestation/target_info` and
 * `/dev/attestation/my_target_info`. This is because the SGX quote always embeds target info
 * of the current enclave.
 */
static int dev_attestation_quote_open(struct shim_handle* hdl, const char* name, int flags) {
    __UNUSED(name);

    if (strcmp_static(PAL_CB(host_type), "Linux-SGX")) {
        /* this pseudo-file is only available with Linux-SGX */
        return -EACCES;
    }

    if (flags & (O_WRONLY | O_RDWR))
        return -EACCES;

    struct shim_str_data* data = calloc(1, sizeof(*data));
    if (!data)
        return -ENOMEM;

    uint8_t quote[SGX_QUOTE_MAX_SIZE];
    size_t quote_size = sizeof(quote);

    /* this is the only pseudo-file that uses PAL; all other files are emulated entirely in LibOS */
    int ret = DkAttestationQuote(&g_report_data, sizeof(g_report_data), &quote, &quote_size);
    if (ret < 0) {
        free(data);
        return -EACCES;
    }

    char* data_str_quote = calloc(1, quote_size);
    if (!data_str_quote) {
        free(data);
        return -ENOMEM;
    }

    memcpy(data_str_quote, quote, quote_size);

    data->str       = data_str_quote;
    data->buf_size  = quote_size;
    data->len       = quote_size;

    hdl->type          = TYPE_STR;
    hdl->acc_mode      = MAY_READ;
    hdl->info.str.data = data;
    hdl->info.str.ptr  = data_str_quote;
    return 0;
}

static struct pseudo_fs_ops dev_attestation_report_data_fs_ops = {
    .open = &dev_attestation_report_data_open,
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

struct pseudo_fs_ops dev_attestation_fs_ops = {
    .open = &pseudo_dir_open,
    .mode = &pseudo_dir_mode,
    .stat = &pseudo_dir_stat,
};

struct pseudo_dir dev_attestation_dir = {
    .size = 5,
    .ent  = {
              /* file search logic looks at name prefix, so "report" must come before "report_data" */
              { .name   = "report",
                .fs_ops = &dev_attestation_report_fs_ops,
                .type   = LINUX_DT_REG },
              { .name   = "report_data",
                .fs_ops = &dev_attestation_report_data_fs_ops,
                .type   = LINUX_DT_REG },
              { .name   = "target_info",
                .fs_ops = &dev_attestation_target_info_fs_ops,
                .type   = LINUX_DT_REG },
              { .name   = "my_target_info",
                .fs_ops = &dev_attestation_my_target_info_fs_ops,
                .type   = LINUX_DT_REG },
              { .name   = "quote",
                .fs_ops = &dev_attestation_quote_fs_ops,
                .type   = LINUX_DT_REG },
            }
};
