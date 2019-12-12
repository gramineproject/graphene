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
static __sgx_mem_aligned sgx_report_data_t report_data;

static int proc_sgx_report_stat(const char* name, struct stat* buf) {
    __UNUSED(name);
    __UNUSED(buf);
    __abort();
}

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

    hdl->type          = TYPE_STR;
    hdl->flags         = flags & ~O_RDONLY;
    hdl->acc_mode      = MAY_READ;
    hdl->info.str.data = data;

    return 0;
}

static int proc_sgx_report_mode(const char* name, mode_t* mode) {
    __UNUSED(name);
    *mode = 0444;
    return 0;
}

static int proc_sgx_ias_report_stat(const char* name, struct stat* buf) {
    __UNUSED(name);
    __UNUSED(buf);
    __abort();
}

static int proc_sgx_ias_report_open(struct shim_handle* hdl, const char* name, int flags) {

    __UNUSED(hdl);
    __UNUSED(name);
    __UNUSED(flags);

    struct shim_str_data* data = calloc(1, sizeof(struct shim_str_data));
    if (!data) {
        return -ENOMEM;
    }

    static char ias_report[10 * 1024];
    static PAL_NUM size;
    int ret = DkIASReport(ias_report, sizeof(ias_report), &size);
    if (ret < 0)
        return ret;

    data->str          = (char*) ias_report;
    data->len          = size;

    hdl->type          = TYPE_STR;
    hdl->flags         = flags & ~O_RDONLY;
    hdl->acc_mode      = MAY_READ;
    hdl->info.str.data = data;

    return 0;
}

static int proc_sgx_ias_report_mode(const char* name, mode_t* mode) {
    __UNUSED(name);
    *mode = 0444;
    return 0;
}

static int proc_sgx_my_target_info_stat(const char* name, struct stat* buf) {
    __UNUSED(name);
    __UNUSED(buf);
    __abort();
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
    __UNUSED(hdl);
    __UNUSED(name);
    __UNUSED(flags);

    sgx_target_info_t* target_info = malloc(sizeof(*target_info));
    if (!target_info) {
        return -ENOMEM;
    }

    struct shim_str_data* data = calloc(1, sizeof(struct shim_str_data));
    if (!data) {
        free(target_info);
        return -ENOMEM;
    }

    sgx_target_info(target_info);

    data->str          = (char*) target_info;
    data->len          = sizeof(*target_info);

    hdl->type          = TYPE_STR;
    hdl->flags         = flags & ~O_RDONLY;
    hdl->acc_mode      = MAY_READ;
    hdl->info.str.data = data;

    return 0;
}

static int proc_sgx_my_target_info_mode(const char* name, mode_t* mode) {
    __UNUSED(name);
    *mode = 0444;
    return 0;
}

static int proc_sgx_target_info_stat(const char* name, struct stat* buf) {
    __UNUSED(name);
    __UNUSED(buf);
    __abort();
}

static int proc_sgx_target_info_open(struct shim_handle* hdl, const char* name, int flags) {
    __UNUSED(name);

    struct shim_str_data* data = calloc(1, sizeof(struct shim_str_data));
    if (!data) {
        return -ENOMEM;
    }

    data->str          = (char*) &target_info;
    data->buf_size     = sizeof(target_info);
    data->len          = 0;

    hdl->type          = TYPE_STR;
    hdl->flags         = flags & ~O_RDWR;
    hdl->acc_mode      = MAY_WRITE;
    hdl->info.str.data = data;
    hdl->info.str.ptr  = (char*) &target_info;

    return 0;
}

static int proc_sgx_target_info_mode(const char* name, mode_t* mode) {
    __UNUSED(name);
    *mode = 0666;
    return 0;
}

static int proc_sgx_report_data_stat(const char* name, struct stat* buf) {
    __UNUSED(name);
    __UNUSED(buf);
    __abort();
}

static int proc_sgx_report_data_open(struct shim_handle* hdl, const char* name, int flags) {

    struct shim_str_data* data = calloc(1, sizeof(struct shim_str_data));
    if (!data) {
        return -ENOMEM;
    }

    data->str          = (char*) &report_data;
    data->buf_size     = sizeof(report_data);
    data->len          = 0;

    hdl->type          = TYPE_STR;
    hdl->flags         = flags & ~O_RDWR;
    hdl->acc_mode      = MAY_WRITE;
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
    .stat = &proc_sgx_report_stat,
};

static struct proc_fs_ops fs_sgx_ias_report = {
    .open = &proc_sgx_ias_report_open,
    .mode = &proc_sgx_ias_report_mode,
    .stat = &proc_sgx_ias_report_stat,
};

static struct proc_fs_ops fs_sgx_my_target_info = {
    .open = &proc_sgx_my_target_info_open,
    .mode = &proc_sgx_my_target_info_mode,
    .stat = &proc_sgx_my_target_info_stat,
};

static struct proc_fs_ops fs_sgx_target_info = {
    .open = &proc_sgx_target_info_open,
    .mode = &proc_sgx_target_info_mode,
    .stat = &proc_sgx_target_info_stat,
};

static struct proc_fs_ops fs_sgx_report_data = {
    .open = &proc_sgx_report_data_open,
    .mode = &proc_sgx_report_data_mode,
    .stat = &proc_sgx_report_data_stat,
};

struct proc_dir dir_sgx = {
    .size = 5,
    .ent =
        {
            {
                .name   = "report",
                .fs_ops = &fs_sgx_report,
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
                .name   = "target_info",
                .fs_ops = &fs_sgx_target_info,
            },
            {
                .name   = "report_data",
                .fs_ops = &fs_sgx_report_data,
            },
        },
};
