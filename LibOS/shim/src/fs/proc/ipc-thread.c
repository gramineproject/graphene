/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <shim_internal.h>
#include <shim_table.h>
#include <shim_thread.h>
#include <shim_handle.h>
#include <shim_fs.h>
#include <shim_utils.h>
#include <shim_ipc.h>

#include <pal.h>
#include <pal_error.h>

#include <errno.h>

#include <linux/stat.h>
#include <linux/fcntl.h>

#include <asm/fcntl.h>
#include <asm/mman.h>
#include <asm/unistd.h>
#include <asm/prctl.h>

static int parse_ipc_thread_name (const char * name,
                                  const char ** next, int * next_len,
                                  const char ** nextnext)
{
    const char * p = name;
    int pid = 0;

    if (*p == '/')
        p++;

    for ( ; *p && *p != '/' ; p++) {
        if (*p < '0' || *p > '9')
            return -ENOENT;

        pid = pid * 10 + *p - '0';
    }

    if (next) {
        if (*(p++) == '/' && *p) {
            *next = p;

            if (next_len || nextnext)
                for ( ; *p && *p != '/' ; p++);

            if (next_len)
                *next_len = p - *next;

            if (nextnext)
                *nextnext = (*(p++) == '/' && *p) ? p : NULL;
        } else {
            *next = NULL;
        }
    }

    return pid;
}

static int find_ipc_thread_link (const char * name, struct shim_qstr * link,
                                 struct shim_dentry ** dentptr)
{
    const char * next, * nextnext;
    int next_len;

    int pid = parse_ipc_thread_name(name, &next, &next_len, &nextnext);

    if (pid < 0)
        return pid;

    struct shim_dentry * dent = NULL;
    enum pid_meta_code ipc_code;
    void * ipc_data = NULL;
    int ret = 0;

    if (!memcmp(next, "root", next_len)) {
        ipc_code = PID_META_ROOT;
        goto do_ipc;
    }

    if (!memcmp(next, "cwd", next_len)) {
        ipc_code = PID_META_CWD;
        goto do_ipc;
    }

    if (!memcmp(next, "exe", next_len)) {
        ipc_code = PID_META_EXEC;
        goto do_ipc;
    }

    ret = -ENOENT;
    goto out;
do_ipc:
    ret = ipc_pid_getmeta_send(pid, ipc_code, &ipc_data);
    if (ret < 0)
        goto out;

    if (link)
        qstrsetstr(link, (char *) ipc_data, strlen((char *) ipc_data));

    if (dentptr) {
        /* XXX: Not sure how to handle this case yet */
        assert (0);
        ret = path_lookupat(NULL, (char *) ipc_data, 0, &dent, NULL);
        if (ret < 0)
            goto out;

        get_dentry(dent);
        *dentptr = dent;
    }

out:
    if (dent)
        put_dentry(dent);
    return ret;
}

static int proc_ipc_thread_link_open (struct shim_handle * hdl,
                                      const char * name, int flags)
{
    struct shim_dentry * dent;

    int ret = find_ipc_thread_link(name, NULL, &dent);
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

static int proc_ipc_thread_link_mode (const char * name, mode_t * mode)
{
    struct shim_dentry * dent;

    int ret = find_ipc_thread_link(name, NULL, &dent);
    if (ret < 0)
        return ret;

    if (!dent->fs || !dent->fs->d_ops || !dent->fs->d_ops->mode) {
        ret = -EACCES;
        goto out;
    }

    ret = dent->fs->d_ops->mode(dent, mode, true);
out:
    put_dentry(dent);
    return ret;
}

static int proc_ipc_thread_link_stat (const char * name, struct stat * buf)
{
    struct shim_dentry * dent;

    int ret = find_ipc_thread_link(name, NULL, &dent);
    if (ret < 0)
        return ret;

    if (!dent->fs || !dent->fs->d_ops || !dent->fs->d_ops->stat) {
        ret = -EACCES;
        goto out;
    }

    ret = dent->fs->d_ops->stat(dent, buf);
out:
    put_dentry(dent);
    return ret;
}

static int proc_ipc_thread_link_follow_link (const char * name,
                                             struct shim_qstr * link)
{
    return find_ipc_thread_link(name, link, NULL);
}

static const struct proc_fs_ops fs_ipc_thread_link = {
            .open           = &proc_ipc_thread_link_open,
            .mode           = &proc_ipc_thread_link_mode,
            .stat           = &proc_ipc_thread_link_stat,
            .follow_link    = &proc_ipc_thread_link_follow_link,
        };

static struct pid_status_cache {
    int ref_count;
    bool dirty;
    int nstatus;
    struct pid_status * status;
} * pid_status_cache;

static LOCKTYPE status_lock;

static int proc_match_ipc_thread (const char * name)
{
    int pid = parse_ipc_thread_name(name, NULL, NULL, NULL);

    if (pid < 0)
        return 0;

    create_lock_runtime(&status_lock);
    lock(status_lock);

    if (pid_status_cache)
        for (int i = 0 ; i < pid_status_cache->nstatus ; i++)
            if (pid_status_cache->status[i].pid == pid) {
                unlock(status_lock);
                return 1;
            }

    unlock(status_lock);
    return 0;
}

static int proc_ipc_thread_dir_mode (const char * name, mode_t * mode)
{
    const char * next;
    int next_len;
    int pid = parse_ipc_thread_name(name, &next, &next_len, NULL);

    if (pid < 0)
        return 0;

    create_lock_runtime(&status_lock);
    lock(status_lock);

    if (pid_status_cache)
        for (int i = 0 ; i < pid_status_cache->nstatus ; i++)
            if (pid_status_cache->status[i].pid == pid) {
                unlock(status_lock);
                *mode = 0500;
                return 0;
            }

    unlock(status_lock);
    return -ENOENT;
}

static int proc_ipc_thread_dir_stat (const char * name, struct stat * buf)
{
    const char * next;
    int next_len;
    int pid = parse_ipc_thread_name(name, &next, &next_len, NULL);

    if (pid < 0)
        return 0;

    create_lock_runtime(&status_lock);
    lock(status_lock);

    if (pid_status_cache)
        for (int i = 0 ; i < pid_status_cache->nstatus ; i++)
            if (pid_status_cache->status[i].pid == pid) {
                memset(buf, 0, sizeof(struct stat));
                buf->st_dev = buf->st_ino = 1;
                buf->st_mode = 0500|S_IFDIR;
                buf->st_uid = 0; /* XXX */
                buf->st_gid = 0; /* XXX */
                buf->st_size = 4096;
                unlock(status_lock);
                return 0;
            }

    unlock(status_lock);
    return -ENOENT;
}

int get_all_pid_status (struct pid_status ** status);

static int proc_list_ipc_thread (const char * name, struct shim_dirent ** buf,
                                 int len)
{
    struct pid_status_cache * status = NULL;
    int ret = 0;

    create_lock_runtime(&status_lock);

    lock(status_lock);
    if (pid_status_cache && !pid_status_cache->dirty) {
        status = pid_status_cache;
        status->ref_count++;
    }
    unlock(status_lock);

    if (!status) {
        status = malloc(sizeof(struct pid_status_cache));
        if (!status)
            return -ENOMEM;

        ret = get_all_pid_status(&status->status);
        if (ret < 0) {
            free(status);
            return ret;
        }

        status->nstatus = ret;
        status->ref_count = 1;
        status->dirty = false;

        lock(status_lock);
        if (pid_status_cache) {
            if (pid_status_cache->dirty) {
                if (!pid_status_cache->ref_count)
                    free(pid_status_cache);
                pid_status_cache = status;
            } else {
                if (status->nstatus)
                    free(status->status);
                free(status);
                status = pid_status_cache;
                status->ref_count++;
            }
        } else {
            pid_status_cache = status;
        }
        unlock(status_lock);
    }

    if (!status->nstatus)
        goto success;

    struct shim_dirent * ptr = (*buf);
    void * buf_end = (void *) ptr + len;

    for (int i = 0 ; i < status->nstatus ; i++) {
        if (status->status[i].pid != status->status[i].tgid)
            continue;

        IDTYPE pid = status->status[i].pid;
        int p = pid, l = 0;
        for ( ; p ; p /= 10, l++);

        if ((void *) (ptr + 1) + l + 1 > buf_end) {
            ret = -ENOBUFS;
            goto err;
        }

        ptr->next = (void *) (ptr + 1) + l + 1;
        ptr->ino = 1;
        ptr->type = LINUX_DT_DIR;
        ptr->name[l--] = 0;
        for (p = pid ; p ; p /= 10)
            ptr->name[l--] = p % 10 + '0';

        ptr = ptr->next;
    }

    *buf = ptr;
success:
    lock(status_lock);
    status->dirty = true;
    status->ref_count--;
    if (!status->ref_count && status != pid_status_cache)
        free(status);
    unlock(status_lock);
    return 0;
err:
    lock(status_lock);
    status->ref_count--;
    if (!status->ref_count && status != pid_status_cache)
        free(status);
    unlock(status_lock);
    return ret;
}

const struct proc_nm_ops nm_ipc_thread = {
            .match_name = &proc_match_ipc_thread,
            .list_name  = &proc_list_ipc_thread,
        };

const struct proc_fs_ops fs_ipc_thread = {
            .mode   = &proc_ipc_thread_dir_mode,
            .stat   = &proc_ipc_thread_dir_stat,
        };

const struct proc_dir dir_ipc_thread = { .size = 0, .ent = {
        { .name = "cwd",  .fs_ops = &fs_ipc_thread_link, },
        { .name = "exe",  .fs_ops = &fs_ipc_thread_link, },
        { .name = "root", .fs_ops = &fs_ipc_thread_link, },
    }, };
