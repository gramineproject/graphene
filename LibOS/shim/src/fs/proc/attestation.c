#include <asm/fcntl.h>
#include <asm/mman.h>
#include <asm/prctl.h>
#include <asm/unistd.h>
#include <errno.h>
#include <linux/fcntl.h>
#include <pal.h>
#include <pal_error.h>
#include <shim_fs.h>
#include <shim_internal.h>

#include "sgx_api.h"
#include "sgx_attest.h"

// TODO: For some reason S_IF* macros are missing if this file is included before our headers. We
// should investigate and fix this behavior.
#include <linux/stat.h>

static int proc_sgx_attestation_mode(const char* name, mode_t* mode) {
    // The path is implicitly set by calling this function
    __UNUSED(name);
    *mode = 0444;
    return 0;
}

static int proc_sgx_attestation_stat(const char* name, struct stat* buf) {
    // The path is implicitly set by calling this function
    __UNUSED(name);
    memset(buf, 0, sizeof(struct stat));
    buf->st_dev = buf->st_ino = 1;
    buf->st_mode              = 0444 | S_IFREG;
    buf->st_uid               = 0;
    buf->st_gid               = 0;
    buf->st_size              = 0;
    return 0;
}

static __sgx_mem_aligned sgx_report_t report;
static __sgx_mem_aligned sgx_target_info_t target_info;
static __sgx_mem_aligned sgx_target_info_t my_target_info;
static __sgx_mem_aligned sgx_report_data_t report_data;

/* IAS interactions are cached and only repeated if this variable is false. */
static int    ias_valid = 0;
static char   ias_report[10 * 1024];
static char   ias_header[10 * 1024];
static size_t ias_report_size = sizeof(ias_report);
static size_t ias_header_size = sizeof(ias_header);
static int    quote_valid = 0;
static uint8_t quote[2048];
static size_t quote_size = sizeof(quote);

static int proc_sgx_report_open(struct shim_handle* hdl, const char* name, int flags) {
    __UNUSED(name);

    if (flags & (O_WRONLY | O_RDWR))
        return -EACCES;

    struct shim_str_data* data = calloc(1, sizeof(struct shim_str_data));
    if (!data) {
        /* free(str); */
        return -ENOMEM;
    }

    sgx_report(&target_info, &report_data, &report);

    data->str          = (char*) &report;
    data->len          = sizeof(sgx_report_t);
    data->do_not_free  = 1;

    hdl->type          = TYPE_STR;
    hdl->flags         = flags & ~O_RDONLY;
    hdl->acc_mode      = MAY_READ;
    hdl->info.str.data = data;
    hdl->info.str.ptr  = (char*) &report;

    return 0;
}

static int proc_sgx_report_mode(const char* name, mode_t* mode) {
    __UNUSED(name);
    *mode = 0444;
    return 0;
}

static int proc_sgx_ias_header_open(struct shim_handle* hdl, const char* name, int flags) {
    __UNUSED(name);

    struct shim_str_data* data = calloc(1, sizeof(struct shim_str_data));
    if (!data) {
        return -ENOMEM;
    }

    if (!ias_valid) {
        ias_report_size = sizeof(ias_report);
        ias_header_size = sizeof(ias_header);
        int ret = DkIASReport(&report_data, ias_report, &ias_report_size, ias_header,
                              &ias_header_size);
        if (ret < 0)
            return ret;
        ias_valid = 1;
    }

    data->str          = (char*) ias_header;
    data->len          = ias_header_size;
    data->do_not_free  = 1;

    hdl->type          = TYPE_STR;
    hdl->flags         = flags & ~O_RDONLY;
    hdl->acc_mode      = MAY_READ;
    hdl->info.str.data = data;
    hdl->info.str.ptr  = (char*) ias_header;

    return 0;
}

static int proc_sgx_ias_header_mode(const char* name, mode_t* mode) {
    __UNUSED(name);
    *mode = 0444;
    return 0;
}

static int proc_sgx_ias_report_open(struct shim_handle* hdl, const char* name, int flags) {
    __UNUSED(name);

    struct shim_str_data* data = calloc(1, sizeof(struct shim_str_data));
    if (!data) {
        return -ENOMEM;
    }

    if (!ias_valid) {
        ias_report_size = sizeof(ias_report);
        ias_header_size = sizeof(ias_header);
        int ret = DkIASReport(&report_data, ias_report, &ias_report_size, ias_header,
                              &ias_header_size);
        if (ret < 0)
            return ret;
        ias_valid = 1;
    }

    data->str          = (char*) ias_report;
    data->len          = ias_report_size;
    data->do_not_free  = 1;

    hdl->type          = TYPE_STR;
    hdl->flags         = flags & ~O_RDONLY;
    hdl->acc_mode      = MAY_READ;
    hdl->info.str.data = data;
    hdl->info.str.ptr  = (char*) ias_report;

    return 0;
}

static int proc_sgx_ias_report_mode(const char* name, mode_t* mode) {
    __UNUSED(name);
    *mode = 0444;
    return 0;
}

/**
 * Populates an sgx_target_info_t structure with all the information necessary for local
 * attestation.
 *
 * The resulting sgx_target_info_t structure can be passed to another enclave as part of the local
 * attestation flow.
 */
int sgx_target_info(sgx_target_info_t* ti) {

    __sgx_mem_aligned sgx_target_info_t target_info = {0, };
    __sgx_mem_aligned sgx_report_t report;
    __sgx_mem_aligned sgx_report_data_t report_data = {0, };

    int ret = sgx_report(&target_info, &report_data, &report);
    if (ret < 0) return ret;

    memset(ti, 0, sizeof(*ti));
    memcpy(&ti->attributes, &report.body.attributes, sizeof(ti->attributes));
    memcpy(&ti->config_id, &report.body.config_id, sizeof(ti->config_id));
    memcpy(&ti->config_svn, &report.body.config_svn, sizeof(ti->config_svn));
    memcpy(&ti->misc_select, &report.body.misc_select, sizeof(ti->misc_select));
    memcpy(&ti->mr_enclave, &report.body.mr_enclave, sizeof(ti->mr_enclave));

    return 0;
}

static int proc_sgx_my_target_info_open(struct shim_handle* hdl, const char* name, int flags) {
    __UNUSED(name);

    struct shim_str_data* data = calloc(1, sizeof(struct shim_str_data));
    if (!data) {
        return -ENOMEM;
    }

    sgx_target_info(&my_target_info);

    data->str          = (char*) &my_target_info;
    data->len          = sizeof(my_target_info);
    data->do_not_free  = 1;

    hdl->type          = TYPE_STR;
    hdl->flags         = flags & ~O_RDONLY;
    hdl->acc_mode      = MAY_READ;
    hdl->info.str.data = data;
    hdl->info.str.ptr  = (char*) &my_target_info;

    return 0;
}

static int proc_sgx_my_target_info_mode(const char* name, mode_t* mode) {
    __UNUSED(name);
    *mode = 0444;
    return 0;
}

static int proc_sgx_quote_open(struct shim_handle* hdl, const char* name, int flags) {
    __UNUSED(name);

    struct shim_str_data* data = calloc(1, sizeof(struct shim_str_data));
    if (!data) {
        return -ENOMEM;
    }

    if (!quote_valid) {
        size_t quote_size = sizeof(quote);
        int ret = DkSGXQuote(&report_data, sizeof(report_data), quote, &quote_size);
        if (ret < 0)
            return ret;
        quote_valid = 1;
    }

    data->str          = (char*) &quote;
    data->buf_size     = sizeof(quote);
    data->len          = sizeof(quote);
    data->do_not_free  = 1;

    hdl->type          = TYPE_STR;
    hdl->flags         = flags & ~O_RDONLY;
    hdl->acc_mode      = MAY_READ;
    hdl->info.str.data = data;
    hdl->info.str.ptr  = (char*) &quote;

    return 0;
}

static int proc_sgx_quote_mode(const char* name, mode_t* mode) {
    __UNUSED(name);
    *mode = 0666;
    return 0;
}

static int proc_sgx_target_info_open(struct shim_handle* hdl, const char* name, int flags) {
    __UNUSED(name);

    struct shim_str_data* data = calloc(1, sizeof(struct shim_str_data));
    if (!data) {
        return -ENOMEM;
    }

    data->str          = (char*) &target_info;
    data->buf_size     = sizeof(target_info);
    data->len          = sizeof(target_info);
    data->do_not_free  = 1;

    hdl->type          = TYPE_STR;
    hdl->flags         = flags & ~O_RDWR;
    hdl->acc_mode      = MAY_WRITE | MAY_READ;
    hdl->info.str.data = data;
    hdl->info.str.ptr  = (char*) &target_info;

    return 0;
}

static int proc_sgx_target_info_mode(const char* name, mode_t* mode) {
    __UNUSED(name);
    *mode = 0666;
    return 0;
}

/**
 * Invalidate cached IAS report and quote.
 *
 * Since the report_data field changed, a new interaction with IAS is required to reflect the
 * changed report_data in the IAS response. Same for the quote.
 */
static int report_data_modify(struct shim_handle* hdl) {
    ias_valid = quote_valid = 0;
    return 0;
}

static int proc_sgx_report_data_open(struct shim_handle* hdl, const char* name, int flags) {
    __UNUSED(name);

    struct shim_str_data* data = calloc(1, sizeof(struct shim_str_data));
    if (!data) {
        return -ENOMEM;
    }

    data->str          = (char*) &report_data;
    data->buf_size     = sizeof(report_data);
    data->len          = sizeof(report_data);
    data->do_not_free  = 1;
    data->modify       = report_data_modify;

    hdl->type          = TYPE_STR;
    hdl->flags         = flags & ~O_RDWR;
    hdl->acc_mode      = MAY_WRITE | MAY_READ;
    hdl->info.str.data = data;
    hdl->info.str.ptr  = (char*) &report_data;

    return 0;
}

static int proc_sgx_report_data_mode(const char* name, mode_t* mode) {
    __UNUSED(name);
    *mode = 0666;
    return 0;
}

struct proc_fs_ops fs_sgx_attestation = {
    .mode = &proc_sgx_attestation_mode,
    .stat = &proc_sgx_attestation_stat,
};

static struct proc_fs_ops fs_sgx_report = {
    .open = &proc_sgx_report_open,
    .mode = &proc_sgx_report_mode,
    .stat = &proc_sgx_attestation_stat,
};

static struct proc_fs_ops fs_sgx_ias_header = {
    .open = &proc_sgx_ias_header_open,
    .mode = &proc_sgx_ias_header_mode,
    .stat = &proc_sgx_attestation_stat,
};

static struct proc_fs_ops fs_sgx_ias_report = {
    .open = &proc_sgx_ias_report_open,
    .mode = &proc_sgx_ias_report_mode,
    .stat = &proc_sgx_attestation_stat,
};

static struct proc_fs_ops fs_sgx_my_target_info = {
    .open = &proc_sgx_my_target_info_open,
    .mode = &proc_sgx_my_target_info_mode,
    .stat = &proc_sgx_attestation_stat,
};

static struct proc_fs_ops fs_sgx_quote = {
    .open = &proc_sgx_quote_open,
    .mode = &proc_sgx_quote_mode,
    .stat = &proc_sgx_attestation_stat,
};

static struct proc_fs_ops fs_sgx_target_info = {
    .open = &proc_sgx_target_info_open,
    .mode = &proc_sgx_target_info_mode,
    .stat = &proc_sgx_attestation_stat,
};

static struct proc_fs_ops fs_sgx_report_data = {
    .open = &proc_sgx_report_data_open,
    .mode = &proc_sgx_report_data_mode,
    .stat = &proc_sgx_attestation_stat,
};

struct proc_dir dir_sgx = {
    .size = 7,
    .ent =
        {
            {
                .name   = "report",
                .fs_ops = &fs_sgx_report,
            },
            {
                .name   = "ias_header",
                .fs_ops = &fs_sgx_ias_header,
            },
            {
                .name   = "ias_report",
                .fs_ops = &fs_sgx_ias_report,
            },
            {
                .name   = "my_target_info",
                .fs_ops = &fs_sgx_my_target_info,
            },
            {
                .name   = "quote",
                .fs_ops = &fs_sgx_quote,
            },
            {
                .name   = "target_info",
                .fs_ops = &fs_sgx_target_info,
            },
            {
                .name   = "report_data",
                .fs_ops = &fs_sgx_report_data,
            },
        },
};
