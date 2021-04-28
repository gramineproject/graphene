#include <asm/fcntl.h>
#include <asm/mman.h>
#include <asm/unistd.h>
#include <errno.h>
#include <linux/fcntl.h>
#include <stdalign.h>

#include "pal.h"
#include "pal_error.h"
#include "perm.h"
#include "shim_fs.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_lock.h"
#include "shim_process.h"
#include "shim_table.h"
#include "shim_thread.h"
#include "shim_utils.h"
#include "stat.h"
#include "shim_vma.h"

static int parse_thread_name(const char* name, IDTYPE* pidptr, const char** next, size_t* next_len,
                             const char** nextnext) {
    const char* p = name;
    IDTYPE pid    = 0;

    if (*p == '/')
        p++;

    if (strstartswith(p, "self")) {
        p += static_strlen("self");
        if (*p && *p != '/')
            return -ENOENT;
        pid = get_cur_tid();
    } else {
        for (; *p && *p != '/'; p++) {
            if (*p < '0' || *p > '9')
                return -ENOENT;

            pid = pid * 10 + *p - '0';
        }
    }

    if (next) {
        if (*(p++) == '/' && *p) {
            *next = p;

            if (next_len || nextnext)
                for (; *p && *p != '/'; p++)
                    ;

            if (next_len)
                *next_len = p - *next;

            if (nextnext)
                *nextnext = (*(p++) == '/' && *p) ? p : NULL;
        } else {
            *next = NULL;
        }
    }

    if (pidptr)
        *pidptr = pid;
    return 0;
}

static int find_thread_link(const char* name, struct shim_qstr* link,
                            struct shim_dentry** dentptr) {
    const char* next;
    const char* nextnext;
    size_t next_len;
    IDTYPE pid;
    int ret = parse_thread_name(name, &pid, &next, &next_len, &nextnext);
    if (ret < 0)
        return ret;

    struct shim_thread* thread = lookup_thread(pid);
    struct shim_dentry* dent   = NULL;

    if (!thread)
        return -ENOENT;
    /* We just checked that a thread with this id exists and we do not need this handle anymore. */
    put_thread(thread);

    lock(&g_process.fs_lock);

    if (next_len == static_strlen("root") && !memcmp(next, "root", next_len)) {
        dent = g_process.root;
        get_dentry(dent);
    }

    if (next_len == static_strlen("cwd") && !memcmp(next, "cwd", next_len)) {
        dent = g_process.cwd;
        get_dentry(dent);
    }

    if (next_len == static_strlen("exe") && !memcmp(next, "exe", next_len)) {
        struct shim_handle* exec = g_process.exec;
        if (!exec->dentry) {
            unlock(&g_process.fs_lock);
            ret = -EINVAL;
            goto out;
        }
        dent = exec->dentry;
        get_dentry(dent);
    }

    unlock(&g_process.fs_lock);

    if (nextnext) {
        struct shim_dentry* next_dent = NULL;

        ret = path_lookupat(dent, nextnext, LOOKUP_FOLLOW, &next_dent);
        if (ret < 0)
            goto out;

        put_dentry(dent);
        dent = next_dent;
    }

    if (link && !dentry_get_path_into_qstr(dent, link)) {
        ret = -ENOMEM;
        goto out;
    }

    if (dentptr) {
        get_dentry(dent);
        *dentptr = dent;
    }

    ret = 0;
out:
    if (dent)
        put_dentry(dent);
    return ret;
}

static int proc_thread_link_open(struct shim_handle* hdl, const char* name, int flags) {
    struct shim_dentry* dent;

    int ret = find_thread_link(name, NULL, &dent);
    if (ret < 0)
        return ret;

    if (!dent->fs || !dent->fs->d_ops || !dent->fs->d_ops->open) {
        ret = -EACCES;
        goto out;
    }

    ret = dent->fs->d_ops->open(hdl, dent, flags);
out:
    put_dentry(dent);
    return 0;
}

static int proc_thread_link_mode(const char* name, mode_t* mode) {
    struct shim_dentry* dent;

    int ret = find_thread_link(name, NULL, &dent);
    if (ret < 0)
        return ret;

    if (!dent->fs || !dent->fs->d_ops || !dent->fs->d_ops->mode) {
        ret = -EACCES;
        goto out;
    }

    ret = dent->fs->d_ops->mode(dent, mode);
out:
    put_dentry(dent);
    return ret;
}

static int proc_thread_link_stat(const char* name, struct stat* buf) {
    __UNUSED(name);
    memset(buf, 0, sizeof(*buf));

    buf->st_dev = buf->st_ino = 1;
    buf->st_mode              = PERM_r________ | S_IFLNK;
    buf->st_uid               = 0;
    buf->st_gid               = 0;
    buf->st_size              = 0;

    return 0;
}

static int proc_thread_link_follow_link(const char* name, struct shim_qstr* link) {
    return find_thread_link(name, link, NULL);
}

static const struct pseudo_fs_ops fs_thread_link = {
    .open        = &proc_thread_link_open,
    .mode        = &proc_thread_link_mode,
    .stat        = &proc_thread_link_stat,
    .follow_link = &proc_thread_link_follow_link,
};

/* If *phdl is returned on success, the ref count is incremented */
static int parse_thread_fd(const char* name, const char** rest, struct shim_handle** phdl) {
    const char* next;
    const char* nextnext;
    size_t next_len;
    IDTYPE pid;
    int ret = parse_thread_name(name, &pid, &next, &next_len, &nextnext);
    if (ret < 0)
        return ret;

    if (!next || !nextnext || memcmp(next, "fd", next_len))
        return -EINVAL;

    const char* p = nextnext;
    FDTYPE fd     = 0;

    for (; *p && *p != '/'; p++) {
        if (*p < '0' || *p > '9')
            return -ENOENT;
        fd = fd * 10 + *p - '0';
        if ((uint64_t)fd >= get_rlimit_cur(RLIMIT_NOFILE))
            return -ENOENT;
    }

    struct shim_thread* thread = lookup_thread(pid);

    if (!thread)
        return -ENOENT;

    struct shim_handle_map* handle_map = get_thread_handle_map(thread);

    lock(&handle_map->lock);

    if (fd >= handle_map->fd_top || handle_map->map[fd] == NULL ||
        handle_map->map[fd]->handle == NULL) {
        ret = -ENOENT;
        goto out;
    }

    if (phdl) {
        *phdl = handle_map->map[fd]->handle;
        get_handle(*phdl);
    }

    if (rest)
        *rest = *p ? p + 1 : NULL;

    ret = 0;

out:
    unlock(&handle_map->lock);
    put_thread(thread);
    return ret;
}

static int proc_match_thread_each_fd(const char* name) {
    return parse_thread_fd(name, NULL, NULL) == 0 ? 1 : 0;
}

static int proc_list_thread_each_fd(const char* name, struct shim_dirent** buf, size_t count) {
    const char* next;
    size_t next_len;
    IDTYPE pid;
    int ret = parse_thread_name(name, &pid, &next, &next_len, NULL);
    if (ret < 0)
        return ret;

    if (!next || memcmp(next, "fd", next_len))
        return -EINVAL;

    struct shim_thread* thread = lookup_thread(pid);
    if (!thread)
        return -ENOENT;

    struct shim_handle_map* handle_map = get_thread_handle_map(thread);
    int err = 0;
    size_t bytes = 0;
    struct shim_dirent* dirent = *buf;
    struct shim_dirent** last  = NULL;

    lock(&handle_map->lock);

    for (int i = 0; i < handle_map->fd_size; i++)
        if (handle_map->map[i] && handle_map->map[i]->handle) {
            int d = i, l = 0;
            for (; d; d /= 10, l++)
                ;
            l = l ?: 1;

            bytes += sizeof(struct shim_dirent) + l + 1;
            if (bytes > count) {
                err = -ENOMEM;
                break;
            }

            dirent->next      = (void*)(dirent + 1) + l + 1;
            dirent->ino       = 1;
            dirent->type      = LINUX_DT_LNK;
            dirent->name[0]   = '0';
            dirent->name[l--] = 0;
            for (d = i; d; d /= 10) {
                dirent->name[l--] = '0' + d % 10;
            }
            last   = &dirent->next;
            dirent = dirent->next;
        }

    unlock(&handle_map->lock);
    put_thread(thread);

    if (last)
        *last = NULL;

    *buf = dirent;
    return err;
}

static const struct pseudo_name_ops nm_thread_each_fd = {
    .match_name = &proc_match_thread_each_fd,
    .list_name  = &proc_list_thread_each_fd,
};

static int find_thread_each_fd(const char* name, struct shim_qstr* link,
                               struct shim_dentry** dentptr) {
    const char* rest;
    struct shim_handle* handle;
    struct shim_dentry* dent = NULL;
    int ret;

    if ((ret = parse_thread_fd(name, &rest, &handle)) < 0)
        return ret;

    lock(&handle->lock);

    if (handle->dentry) {
        dent = handle->dentry;
        get_dentry(dent);
    }

    unlock(&handle->lock);

    if (!dent) {
        ret = -ENOENT;
        goto out;
    }

    if (rest) {
        struct shim_dentry* next_dent = NULL;

        ret = path_lookupat(dent, rest, LOOKUP_NO_FOLLOW, &next_dent);
        if (ret < 0)
            goto out;

        put_dentry(dent);
        dent = next_dent;
    }

    if (link && !dentry_get_path_into_qstr(dent, link)) {
        ret = -ENOMEM;
        goto out;
    }

    if (dentptr) {
        get_dentry(dent);
        *dentptr = dent;
    }

out:
    if (dent)
        put_dentry(dent);

    put_handle(handle);
    return ret;
}

static int proc_thread_each_fd_open(struct shim_handle* hdl, const char* name, int flags) {
    struct shim_dentry* dent;

    int ret = find_thread_each_fd(name, NULL, &dent);
    if (ret < 0)
        return ret;

    if (!dent->fs || !dent->fs->d_ops || !dent->fs->d_ops->open) {
        ret = -EACCES;
        goto out;
    }

    ret = dent->fs->d_ops->open(hdl, dent, flags);
out:
    put_dentry(dent);
    return 0;
}

static int proc_thread_each_fd_mode(const char* name, mode_t* mode) {
    struct shim_dentry* dent;

    int ret = find_thread_each_fd(name, NULL, &dent);
    if (ret < 0)
        return ret;

    if (!dent->fs || !dent->fs->d_ops || !dent->fs->d_ops->mode) {
        ret = -EACCES;
        goto out;
    }

    ret = dent->fs->d_ops->mode(dent, mode);
out:
    put_dentry(dent);
    return 0;
}

static int proc_thread_each_fd_stat(const char* name, struct stat* buf) {
    struct shim_dentry* dent;

    int ret = find_thread_each_fd(name, NULL, &dent);
    if (ret < 0)
        return ret;

    if (!dent->fs || !dent->fs->d_ops || !dent->fs->d_ops->stat) {
        ret = -EACCES;
        goto out;
    }

    ret = dent->fs->d_ops->stat(dent, buf);
out:
    put_dentry(dent);
    return 0;
}

static int proc_thread_each_fd_follow_link(const char* name, struct shim_qstr* link) {
    return find_thread_each_fd(name, link, NULL);
}

static const struct pseudo_fs_ops fs_thread_each_fd = {
    .open        = &proc_thread_each_fd_open,
    .mode        = &proc_thread_each_fd_mode,
    .stat        = &proc_thread_each_fd_stat,
    .follow_link = &proc_thread_each_fd_follow_link,
};

static const struct pseudo_dir dir_fd = {
    .size = 1,
    .ent =
        {
            {
                .name_ops = &nm_thread_each_fd,
                .fs_ops   = &fs_thread_each_fd,
                .type     = LINUX_DT_LNK,
            },
        },
};

static int proc_thread_maps_open(struct shim_handle* hdl, const char* name, int flags) {
    if (flags & (O_WRONLY | O_RDWR))
        return -EACCES;

    const char* next;
    size_t next_len;
    IDTYPE pid;
    char* buffer = NULL;
    int ret = parse_thread_name(name, &pid, &next, &next_len, NULL);
    if (ret < 0)
        return ret;

    struct shim_thread* thread = lookup_thread(pid);

    if (!thread)
        return -ENOENT;

    size_t count;
    struct shim_vma_info* vmas = NULL;
    ret = dump_all_vmas(&vmas, &count, /*include_unmapped=*/false);
    if (ret < 0) {
        goto err;
    }

#define DEFAULT_VMA_BUFFER_SIZE 256

    size_t buffer_size = DEFAULT_VMA_BUFFER_SIZE, offset = 0;
    buffer = malloc(buffer_size);
    if (!buffer) {
        ret = -ENOMEM;
        goto err;
    }

    for (struct shim_vma_info* vma = vmas; vma < vmas + count; vma++) {
        size_t old_offset = offset;
        uintptr_t start   = (uintptr_t)vma->addr;
        uintptr_t end     = (uintptr_t)vma->addr + vma->length;
        char pt[3]        = {
            (vma->prot & PROT_READ) ? 'r' : '-',
            (vma->prot & PROT_WRITE) ? 'w' : '-',
            (vma->prot & PROT_EXEC) ? 'x' : '-',
        };
        char pr = (vma->flags & MAP_PRIVATE) ? 'p' : 's';

#define ADDR_FMT(addr) ((addr) > 0xffffffff ? "%lx" : "%08lx")
#define EMIT(fmt...)                                                    \
    do {                                                                \
        offset += snprintf(buffer + offset, buffer_size - offset, fmt); \
    } while (0)

    retry_emit_vma:
        if (vma->file) {
            int dev_major = 0, dev_minor = 0;
            unsigned long ino = vma->file->dentry ? vma->file->dentry->ino : 0;
            const char* name  = "[unknown]";

            if (!qstrempty(&vma->file->path))
                name = qstrgetstr(&vma->file->path);

            EMIT(ADDR_FMT(start), start);
            EMIT("-");
            EMIT(ADDR_FMT(end), end);
            EMIT(" %c%c%c%c %08lx %02d:%02d %lu %s\n", pt[0], pt[1], pt[2], pr, vma->file_offset,
                 dev_major, dev_minor, ino, name);
        } else {
            EMIT(ADDR_FMT(start), start);
            EMIT("-");
            EMIT(ADDR_FMT(end), end);
            if (vma->comment[0])
                EMIT(" %c%c%c%c 00000000 00:00 0 %s\n", pt[0], pt[1], pt[2], pr, vma->comment);
            else
                EMIT(" %c%c%c%c 00000000 00:00 0\n", pt[0], pt[1], pt[2], pr);
        }

        if (offset >= buffer_size) {
            char* new_buffer = malloc(buffer_size * 2);
            if (!new_buffer) {
                ret = -ENOMEM;
                goto err;
            }

            offset = old_offset;
            memcpy(new_buffer, buffer, old_offset);
            free(buffer);
            buffer = new_buffer;
            buffer_size *= 2;
            goto retry_emit_vma;
        }
    }

    struct shim_str_data* data = calloc(1, sizeof(struct shim_str_data));
    if (!data) {
        ret = -ENOMEM;
        goto err;
    }

    data->str = buffer;
    data->len = offset;
    hdl->type          = TYPE_STR;
    hdl->flags         = flags & ~O_RDONLY;
    hdl->acc_mode      = MAY_READ;
    hdl->info.str.data = data;
    ret = 0;

err:
    if (ret < 0) {
        free(buffer);
    }
    if (vmas) {
        free_vma_info_array(vmas, count);
    }
    put_thread(thread);
    return ret;
}

static int proc_thread_maps_mode(const char* name, mode_t* mode) {
    // Only used by one file
    __UNUSED(name);
    *mode = PERM_r________;
    return 0;
}

static int proc_thread_maps_stat(const char* name, struct stat* buf) {
    // Only used by one file
    __UNUSED(name);
    memset(buf, 0, sizeof(struct stat));

    buf->st_dev = buf->st_ino = 1;
    buf->st_mode              = PERM_r________ | S_IFREG;
    buf->st_uid               = 0;
    buf->st_gid               = 0;
    buf->st_size              = 0;

    return 0;
}

static const struct pseudo_fs_ops fs_thread_maps = {
    .open = &proc_thread_maps_open,
    .mode = &proc_thread_maps_mode,
    .stat = &proc_thread_maps_stat,
};

static int proc_thread_cmdline_open(struct shim_handle* hdl, const char* name, int flags) {
    if (flags & (O_WRONLY | O_RDWR))
        return -EACCES;

    const char* next;
    size_t next_len;
    char* buffer = NULL;
    IDTYPE pid = 0;

    int ret = parse_thread_name(name, &pid, &next, &next_len, NULL);
    if (ret < 0)
        return ret;

    size_t buffer_size = g_process.cmdline_size;
    buffer = malloc(buffer_size);
    if (!buffer) {
        return -ENOMEM;
    }

    memcpy(buffer, g_process.cmdline, buffer_size);

    struct shim_str_data* data = malloc(sizeof(*data));
    if (!data) {
        free(buffer);
        return -ENOMEM;
    }

    data->str          = buffer;
    data->len          = buffer_size;
    hdl->type          = TYPE_STR;
    hdl->flags         = flags & ~O_RDONLY;
    hdl->acc_mode      = MAY_READ;
    hdl->info.str.data = data;

    return 0;
}

static int proc_thread_cmdline_mode(const char* name, mode_t* mode) {
    // Only used by one file
    __UNUSED(name);
    *mode = PERM_r________;
    return 0;
}

static int proc_thread_cmdline_stat(const char* name, struct stat* buf) {
    // Only used by one file
    __UNUSED(name);
    memset(buf, 0, sizeof(*buf));

    buf->st_dev = buf->st_ino = 1;
    buf->st_mode              = PERM_r________ | S_IFREG;
    buf->st_uid               = 0;
    buf->st_gid               = 0;
    buf->st_size              = 0;

    return 0;
}

static const struct pseudo_fs_ops fs_thread_cmdline = {
    .open = &proc_thread_cmdline_open,
    .mode = &proc_thread_cmdline_mode,
    .stat = &proc_thread_cmdline_stat,
};

static int proc_thread_dir_open(struct shim_handle* hdl, const char* name, int flags) {
    __UNUSED(hdl);
    __UNUSED(name);

    if (flags & (O_WRONLY | O_RDWR))
        return -EISDIR;

    // Don't really need to do any work here, but keeping as a placeholder,
    // just in case.

    return 0;
}

static int proc_thread_dir_mode(const char* name, mode_t* mode) {
    const char* next;
    size_t next_len;
    IDTYPE pid;
    int ret = parse_thread_name(name, &pid, &next, &next_len, NULL);
    if (ret < 0)
        return ret;

    *mode = PERM_r_x______;
    return 0;
}

static int proc_thread_dir_stat(const char* name, struct stat* buf) {
    const char* next;
    size_t next_len;
    IDTYPE pid;
    int ret = parse_thread_name(name, &pid, &next, &next_len, NULL);
    if (ret < 0)
        return ret;

    struct shim_thread* thread = lookup_thread(pid);

    if (!thread)
        return -ENOENT;

    memset(buf, 0, sizeof(struct stat));
    buf->st_dev = buf->st_ino = 1;
    buf->st_mode              = PERM_r_x______ | S_IFDIR;
    lock(&thread->lock);
    buf->st_uid = thread->uid;
    buf->st_gid = thread->gid;
    unlock(&thread->lock);
    buf->st_size = 4096;
    /* FIXME: Libs like hwloc use /proc/[..]/task to estimate the number of TIDs (but later
     * dynamically increase it if needed). Currently we set nlink to 3 (for ".", ".." and one TID);
     * need a more generic solution. */
    buf->st_nlink = 3;

    put_thread(thread);
    return 0;
}

static const struct pseudo_fs_ops fs_thread_fd = {
    .mode = &proc_thread_dir_mode,
    .stat = &proc_thread_dir_stat,
};

static int proc_match_thread(const char* name) {
    IDTYPE pid;
    if (parse_thread_name(name, &pid, NULL, NULL, NULL) < 0)
        return 0;

    struct shim_thread* thread = lookup_thread(pid);

    if (thread) {
        put_thread(thread);
        return 1;
    }

    return 0;
}

struct walk_thread_arg {
    struct shim_dirent *buf, *buf_end;
};

static int walk_cb(struct shim_thread* thread, void* arg) {
    struct walk_thread_arg* args = (struct walk_thread_arg*)arg;
    IDTYPE pid                   = thread->tid;
    int p = pid, l = 0;
    for (; p; p /= 10, l++)
        ;

    /* buf->next below must be properly aligned */
    size_t buflen = ALIGN_UP(l + 1, alignof(struct shim_dirent));

    if ((void*)(args->buf + 1) + buflen > (void*)args->buf_end)
        return -ENOMEM;

    struct shim_dirent* buf = args->buf;

    buf->next      = (void*)(buf + 1) + buflen;
    buf->ino       = 1;
    buf->type      = LINUX_DT_DIR;
    buf->name[l--] = 0;
    for (p = pid; p; p /= 10) {
        buf->name[l--] = p % 10 + '0';
    }

    args->buf = buf->next;
    return 1;
}

static int proc_list_thread(const char* name, struct shim_dirent** buf, size_t size) {
    __UNUSED(name);  // We know this is for "/proc/self"
    struct walk_thread_arg args = {
        .buf     = *buf,
        .buf_end = (void*)*buf + size,
    };

    int ret = walk_thread_list(&walk_cb, &args, /*one_shot=*/false);
    if (ret < 0)
        return ret;

    *buf = args.buf;
    return 0;
}

const struct pseudo_name_ops nm_thread = {
    .match_name = &proc_match_thread,
    .list_name  = &proc_list_thread,
};

const struct pseudo_fs_ops fs_thread = {
    .open = &proc_thread_dir_open,
    .mode = &proc_thread_dir_mode,
    .stat = &proc_thread_dir_stat,
};

static const struct pseudo_dir dir_task = {
    .size = 1,
    .ent  = {
        {.name_ops = &nm_thread, .fs_ops = &fs_thread, .type = LINUX_DT_DIR},
    }
};

const struct pseudo_dir dir_thread = {
    .size = 7,
    .ent  = {
        {.name = "cwd",  .fs_ops = &fs_thread_link, .type = LINUX_DT_LNK},
        {.name = "exe",  .fs_ops = &fs_thread_link, .type = LINUX_DT_LNK},
        {.name = "root", .fs_ops = &fs_thread_link, .type = LINUX_DT_LNK},
        {.name = "fd",   .fs_ops = &fs_thread_fd,   .dir  = &dir_fd,   .type = LINUX_DT_DIR},
        {.name = "maps", .fs_ops = &fs_thread_maps, .type = LINUX_DT_REG},
        {.name = "task", .fs_ops = &fs_thread,      .dir  = &dir_task, .type = LINUX_DT_DIR},
        {.name = "cmdline",  .fs_ops = &fs_thread_cmdline, .type = LINUX_DT_REG},
    }
};
