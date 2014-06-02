/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <shim_internal.h>
#include <shim_fs.h>

#include <pal.h>
#include <pal_error.h>

#include <asm/fcntl.h>
#include <asm/mman.h>
#include <asm/unistd.h>
#include <asm/prctl.h>
#include <errno.h>

#define MEMINFO_READ_PASSTHROUGH 1
#define CPUINFO_READ_PASSTHROUGH 1

static int proc_info_mode (const char * name, mode_t * mode)
{
    *mode = 0444;
    return 0;
}

static int proc_info_stat (const char * name, struct stat * buf)
{
    memset(buf, 0, sizeof(struct stat));

    buf->st_dev = buf->st_ino = 1;
    buf->st_mode = 0444|S_IFDIR;
    buf->st_uid = 0;
    buf->st_gid = 0;
    buf->st_size = 0;

    return 0;
}

#if MEMINFO_READ_PASSTHROUGH == 1 || CPUINFO_READ_PASSTHROUGH == 1

# define DEFAULT_BUFFER_SIZE 256

static int proc_info_read_passthrough (const char * uri, char ** strptr)
{
    int size = DEFAULT_BUFFER_SIZE;
    char * strbuf = malloc(size);
    int bytes = 0, ret = 0;

    if (!strbuf) {
        ret = -ENOMEM;
        goto out;
    }

    PAL_HANDLE hdl = DkStreamOpen(uri, PAL_ACCESS_RDONLY, 0, 0, 0);

    if (!hdl)
        return -PAL_ERRNO;

retry:
    ret = DkStreamRead(hdl, bytes, size - bytes, strbuf + bytes, NULL, 0);

    if (!ret) {
        ret = -PAL_ERRNO;
        goto out_free;
    }

    bytes += ret;

    if (bytes == size) {
        char * newbuf = malloc(size * 2);
        memcpy(newbuf, strbuf, size);
        free(strbuf);
        strbuf = newbuf;
        size *= 2;
        goto retry;
    }

    ret = bytes;
    *strptr = strbuf;
    goto out;

out_free:
    free(strbuf);
out:
    DkObjectClose(hdl);
    return ret;
}
#endif

static int proc_meminfo_open (struct shim_handle * hdl, const char * name,
                              int flags)
{
    if (flags & (O_WRONLY|O_RDWR))
        return -EACCES;

    char * str = NULL;
    int ret = 0, len = 0;
#if MEMINFO_READ_PASSTHROUGH == 1
    ret = proc_info_read_passthrough("file:/proc/meminfo", &str);

    if (ret >= 0) {
        len = ret;
        ret = 0;
    }
#else
    ret = -EACCES;
#endif
    if (ret < 0)
        return ret;

    struct shim_str_data * data = malloc(sizeof(struct shim_str_data));
    if (!data) {
        free(str);
        return -ENOMEM;
    }

    memset(data, 0, sizeof(struct shim_str_data));
    data->str = str;
    data->len = len;
    hdl->type = TYPE_STR;
    hdl->flags = flags & ~O_RDONLY;
    hdl->acc_mode = MAY_READ;
    hdl->info.str.data = data;
    return 0;
}

static int proc_cpuinfo_open (struct shim_handle * hdl, const char * name,
                              int flags)
{
    if (flags & (O_WRONLY|O_RDWR))
        return -EACCES;

    char * str = NULL;
    int ret = 0, len = 0;
#if CPUINFO_READ_PASSTHROUGH == 1
    ret = proc_info_read_passthrough("file:/proc/cpuinfo", &str);

    if (ret >= 0) {
        len = ret;
        ret = 0;
    }
#else
    ret = -EACCES;
#endif
    if (ret < 0)
        return ret;

    struct shim_str_data * data = malloc(sizeof(struct shim_str_data));
    if (!data) {
        free(str);
        return -ENOMEM;
    }

    memset(data, 0, sizeof(struct shim_str_data));
    data->str = str;
    data->len = len;
    hdl->type = TYPE_STR;
    hdl->flags = flags & ~O_RDONLY;
    hdl->acc_mode = MAY_READ;
    hdl->info.str.data = data;
    return 0;
}

struct proc_fs_ops fs_meminfo = {
        .mode     = &proc_info_mode,
        .stat     = &proc_info_stat,
        .open     = &proc_meminfo_open,
    };

struct proc_fs_ops fs_cpuinfo = {
        .mode     = &proc_info_mode,
        .stat     = &proc_info_stat,
        .open     = &proc_cpuinfo_open,
    };
