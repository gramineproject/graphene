/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2014 OSCAR lab, Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * db_process.c
 *
 * This source file contains functions to create a child process and terminate
 * the running process. Child does not inherit any objects or memory from its
 * parent pricess. A Parent process may not modify the execution of its
 * children. It can wait for a child to exit using its handle. Also, parent and
 * child may communicate through I/O streams provided by the parent to the child
 * at creation.
 */

#include "pal_defs.h"
#include "pal_linux_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_debug.h"
#include "pal_error.h"
#include "pal_security.h"
#include "graphene.h"
#include "graphene-ipc.h"
#include "api.h"

#include <linux/sched.h>
#include <linux/types.h>
typedef __kernel_pid_t pid_t;
#include <asm/fcntl.h>
#include <sys/socket.h>
#include <asm-errno.h>

#ifndef SEEK_SET
# define SEEK_SET 0
#endif

int _DkProcessCreate (PAL_HANDLE * handle, const char * uri,
                      int flags, const char ** args)
{
    int ret, rete = 0;

    const char * manifest_uri   = pal_config.manifest;
    PAL_HANDLE   manifest       = pal_config.manifest_handle;
    const char * exec_uri       = NULL;
    PAL_HANDLE   exec           = NULL;
    bool         noexec         = false;

    if (uri) {
        exec_uri = uri;
        if ((ret = _DkStreamOpen(&exec, uri, PAL_ACCESS_RDONLY, 0, 0, 0)) < 0)
            return ret;

        if (check_elf_object(exec) < 0) {
            manifest = exec;
            manifest_uri = uri;
            exec = NULL;
            exec_uri = NULL;
        }
    } else {
        noexec = true;
    }

    int fds[6] = { -1, -1, -1, -1, -1, -1 };

    if (IS_ERR((ret = INLINE_SYSCALL(pipe2, 2, &fds[0], 0))) ||
        IS_ERR((ret = INLINE_SYSCALL(pipe2, 2, &fds[2], 0))) ||
        IS_ERR((ret = INLINE_SYSCALL(socketpair, 4, AF_UNIX, SOCK_STREAM,
                                     0, &fds[4])))) {
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    int proc_fds[2][3] = {
        { fds[0], fds[3], fds[4] },
        { fds[2], fds[1], fds[5] },
    };

    int nargs = 0;
    if (args) {
        const char ** p = args;
        while (*p) {
            p++;
            nargs++;
        }
    }

# define STRARG_SIZE    256

    const char ** new_args = __alloca(sizeof(const char *) * (nargs + 3));
    int bufsize = STRARG_SIZE;
    char * argbuf = __alloca(STRARG_SIZE);
    new_args[0] = pal_config.lib_name;
    new_args[1] = argbuf;
    if (args)
        memcpy(new_args + 2, args, sizeof(const char *) * nargs);
    new_args[nargs + 2] = NULL;

#define write_arg(...)                                      \
    do {                                                    \
        int _len = snprintf(argbuf, bufsize, __VA_ARGS__);  \
        argbuf += _len;                                     \
        bufsize -= _len;                                    \
    } while (0);

    write_arg(":domain=%08x;", pal_sec_info.domain_id);

    int manifest_fd = -1;

    if (manifest) {
        manifest_fd = manifest->file.fd;
        INLINE_SYSCALL(fcntl, 3, manifest_fd, F_SETFD, 0);
        write_arg("manifest=%d,%s;", manifest_fd, manifest_uri ? : "");

        if (manifest != pal_config.manifest_handle)
            manifest_fd = -1;
    }

    write_arg("proc=%d,%d,%d,%d;",
              proc_fds[0][0], proc_fds[0][1], proc_fds[0][2],
              pal_linux_config.pid);

    if (exec) {
        int exec_fd = exec->file.fd;
        INLINE_SYSCALL(fcntl, 3, exec_fd, F_SETFD, 0);
        write_arg("exec=%d,%s;", exec_fd, exec_uri ? : "");
    } else if (noexec) {
        write_arg("noexec;");
    }

    if (pal_sec_info.pipe_prefix)
        write_arg("pipe=%s;", pal_sec_info.pipe_prefix);

    if (pal_config.heap_base)
        write_arg("heap=%lx;", pal_config.heap_base);

    if (pal_sec_info.rand_gen)
        write_arg("rand=%d;", pal_sec_info.rand_gen);

    if (pal_sec_info.mcast_port)
        write_arg("mcast=%u;", pal_sec_info.mcast_port);

    ret = ARCH_VFORK();

    if (IS_ERR(ret)) {
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    if (!ret) {
        for (int i = 0 ; i < 3 ; i++)
            INLINE_SYSCALL(close, 1, proc_fds[1][i]);

        if (manifest_fd >= 0)
            INLINE_SYSCALL(fcntl, 3, manifest_fd, F_SETFD, 0);

        rete = INLINE_SYSCALL(execve, 3, pal_config.lib_name, new_args,
                              pal_config.environments);

        /* shouldn't get to here */
        printf("unexpected failure of new process\n");
        asm("hlt");
        return 0;
    }

    if (IS_ERR(rete)) {
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    for (int i = 0 ; i < 3 ; i++)
        INLINE_SYSCALL(close, 1, proc_fds[0][i]);

    for (int i = 0 ; i < 3 ; i++)
        INLINE_SYSCALL(fcntl, 3, proc_fds[1][i], F_SETFD, FD_CLOEXEC);

    int pid = ret;
    PAL_HANDLE hdl = malloc(HANDLE_SIZE(process));
    SET_HANDLE_TYPE(hdl, process);
    hdl->__in.flags |= RFD(0)|WFD(1)|RFD(2)|WFD(2)|WRITEABLE(1)|WRITEABLE(2);
    hdl->process.stream_in  = proc_fds[1][0];
    hdl->process.stream_out = proc_fds[1][1];
    hdl->process.cargo      = proc_fds[1][2];
    hdl->process.pid = pid;
    hdl->process.nonblocking = PAL_FALSE;
    *handle = hdl;
    ret = 0;
out:
    if (ret < 0) {
        for (int i = 0 ; i < 6 ; i++)
            if (fds[i] >= 0)
                INLINE_SYSCALL(close, 1, fds[i]);
    }

    return ret;
}

static void read_child_args (const char * val, int vlen,
                             void * arg1, bool isnum1,
                             void * arg2, bool isnum2,
                             void * arg3, bool isnum3,
                             void * arg4, bool isnum4)
{
    const char * v1 = val, * v2 = v1, * end = val + vlen;
    void * arg[4] = { arg1, arg2, arg3, arg4 };
    bool isnum[4] = { isnum1, isnum2, isnum3, isnum4 };

    for (int i = 0 ; i < 4 ; i++) {
        if (!arg[i])
            return;

        while (v2 < end && *v2 != ',')
            v2++;

        if (v1 >= end || v2 <= v1) {
            if (isnum[i])
                *(int *) arg[i] = 0;
            else
                ((char *) arg[i])[0] = 0;
            continue;
        }

        if (isnum[i]) {
            *(int *) arg[i] = atoi(v1);
        } else {
            memcpy((char *) arg[i], v1, v2 - v1);
            ((char *) arg[i])[v2 - v1] = 0;
        }

        v2 = v1 = v2 + 1;
    }
}

static inline bool set_fd_cloexec (int fd)
{
    return !(IS_ERR(INLINE_SYSCALL(fcntl, 3, fd, F_SETFD, FD_CLOEXEC)));
}

#define STRARG_SIZE     256

static void read_child_handle (const char * val, int vlen,
                               PAL_HANDLE * handle, const char ** uri)
{
    int fd;
    char buf[STRARG_SIZE];
    read_child_args(val, vlen, &fd, true, buf, false,
                    NULL, false, NULL, false);

    if (!fd || !set_fd_cloexec(fd)) {
        *handle = NULL;
        *uri = NULL;
        return;
    }

    INLINE_SYSCALL(lseek, 3, fd, 0, SEEK_SET);

    int len = strlen(buf);
    PAL_HANDLE hdl = malloc(HANDLE_SIZE(file) + (len > 4 ? len - 4 : 0));
    SET_HANDLE_TYPE(hdl, file);
    hdl->__in.flags |= RFD(0)|WFD(0)|WRITEABLE(0);
    hdl->file.fd = fd;
    if (len > 4) {
        char * path = (void *) hdl + HANDLE_SIZE(file);
        memcpy(path, buf + 5, len - 4);
        hdl->file.realpath = path;
    } else {
        hdl->file.realpath = NULL;
    }
    *handle = hdl;
    *uri = len ? remalloc(buf, len + 1) : NULL;
}

int init_child_process (const char * proc_args)
{
    const char * c = proc_args;

    while (*c) {
        const char * key = c, * val;
        int klen, vlen;

        while (*c && *c != '=' && *c != ';')
            c++;

        klen = c - key;
        if (klen == 6 && !memcmp(key, "noexec", 6))
            /* format: noexec */
            pal_linux_config.noexec = true;

        if (!*c)
            break;
        if (*c == ';') {
            c++;
            continue;
        }

        val = (++c);
        while (*c && *c != ';')
            c++;
        vlen = c - val;
        if (*c == ';')
            c++;

        if (klen == 4) {
            if (!memcmp(key, "exec", 4)) {
                /* format: exec=fd,uri */
                read_child_handle(val, vlen, &pal_config.exec_handle,
                                  &pal_config.exec);
            } else if (!memcmp(key, "proc", 4)) {
                /* format: proc=fd,pid */
                int fds[3], pid;
                read_child_args(val, vlen,
                                &fds[0], true, &fds[1], true, &fds[2], true,
                                &pid, true);

                for (int i = 0 ; i < 3 ; i++)
                    if (!set_fd_cloexec(fds[i]))
                        fds[i] = PAL_IDX_POISON;

                PAL_HANDLE proc = malloc(HANDLE_SIZE(process));
                SET_HANDLE_TYPE(proc, process);
                proc->__in.flags |= RFD(0)|WFD(1)|RFD(2)|WFD(2)|WRITEABLE(1)|WRITEABLE(2);
                proc->process.stream_in  = fds[0];
                proc->process.stream_out = fds[1];
                proc->process.cargo      = fds[2];
                proc->process.pid = pid;
                __pal_control.parent_process = proc;
            } else if (!memcmp(key, "pipe", 4)) {
                /* format: pipe=prefix */
                char * prefix = remalloc(val, vlen + 1);
                prefix[vlen] = 0;
                pal_sec_info.pipe_prefix = prefix;
            } else if (!memcmp(key, "rand", 4)) {
                /* format: rand=fd */
                pal_sec_info.rand_gen = atoi(val);
            } else if (!memcmp(key, "heap", 4)) {
                /* format: heap=addr (hex) */
                pal_config.heap_base = (void *) strtol(val, NULL, 16);
            }
        } else if (klen == 5) {
            if (!memcmp(key, "mcast", 5)) {
                /* format: mcast=port */
                pal_sec_info.mcast_port = atoi(val);
            }
        } else if (klen == 6) {
            if (!memcmp(key, "domain", 6)) {
                /* format: domain=id */
                pal_sec_info.domain_id = strtol(val, NULL, 16);
            }
        } else if (klen == 8) {
            if (!memcmp(key, "manifest", 8)) {
                /* format: manifest=fd,uri */
                read_child_handle(val, vlen, &pal_config.manifest_handle,
                                  &pal_config.manifest);
            }
        }
    }

    return 0;
}

void _DkProcessExit (int exitcode)
{
    if (__pal_control.parent_process)
        _DkObjectClose(__pal_control.parent_process);

    if (__pal_control.manifest_handle)
        _DkObjectClose(__pal_control.manifest_handle);

    INLINE_SYSCALL(exit_group, 1, exitcode);
}

int ioctl_set_graphene (struct config_store * config, int ndefault,
                        const struct graphene_user_policy * default_policies);

static int set_graphene_task (const char * uri, int flags)
{
    PAL_HANDLE handle = NULL;
    int ret;

    if ((ret = _DkStreamOpen(&handle, uri, PAL_ACCESS_RDONLY, 0, 0, 0)) < 0)
        return ret;

    PAL_STREAM_ATTR attr;

    if ((ret = _DkStreamAttributesQuerybyHandle(handle, &attr)) < 0)
        goto out;

    void * addr = NULL;
    size_t size = attr.size;

    if ((ret = _DkStreamMap(handle, &addr, PAL_PROT_READ, 0,
                            ALLOC_ALIGNUP(size))) < 0)
        goto out;

    struct config_store cfg;
    cfg.raw_data = addr;
    cfg.raw_size = size;
    cfg.malloc = malloc;
    cfg.free = free;

    if ((ret = read_config(&cfg, NULL, NULL)) < 0)
        goto out_mem;

    const char * manifest = uri;

    struct graphene_user_policy manifest_policy;
    if (!memcmp(manifest, "file:", 5)) {
        manifest_policy.type = GRAPHENE_FS_PATH | GRAPHENE_FS_READ;
        manifest_policy.value = manifest + 5;
    } else {
        manifest_policy.type = 0;
    }

    if (flags & PAL_SANDBOX_PIPE) {
        do {
            getrand(&pal_sec_info.mcast_port, sizeof(unsigned short));
        } while (pal_sec_info.mcast_port < 1024);
    }

    struct graphene_net_policy mcast_rules[2];
    memset(mcast_rules, 0, sizeof(struct graphene_net_policy) * 2);

    mcast_rules[0].family = AF_INET;
    mcast_rules[0].local.port_begin = pal_sec_info.mcast_port;
    mcast_rules[0].local.port_end = pal_sec_info.mcast_port;
    mcast_rules[0].peer.port_begin = 0;
    mcast_rules[0].peer.port_end = 65535;

    mcast_rules[1].family = AF_INET;
    mcast_rules[1].local.port_begin = 0;
    mcast_rules[1].local.port_end = 65535;
    inet_pton(AF_INET, MCAST_GROUP, &mcast_rules[1].peer.addr);
    mcast_rules[1].peer.port_begin = pal_sec_info.mcast_port;
    mcast_rules[1].peer.port_end = pal_sec_info.mcast_port;

    if (flags & PAL_SANDBOX_PIPE) {
        char pipe_root[GRAPHENE_PIPEDIR_LEN + 20];
        char pipe_prefix[9];
        int sandboxid;

        snprintf(pipe_root,
                 GRAPHENE_PIPEDIR_LEN + 20, GRAPHENE_PIPEDIR "/%08x",
                 pal_sec_info.domain_id);

        getrand(&sandboxid, sizeof(int));
        snprintf(pipe_prefix, 9, "%08x", sandboxid);

        struct graphene_user_policy default_policies[] = {
            { .type = GRAPHENE_UNIX_ROOT,    .value = pipe_root, },
            { .type = GRAPHENE_UNIX_PREFIX,  .value = pipe_prefix, },
            { .type = GRAPHENE_NET_RULE,     .value = &mcast_rules[0], },
            { .type = GRAPHENE_NET_RULE,     .value = &mcast_rules[1], },
            manifest_policy,
        };

        ret = ioctl_set_graphene(&cfg, manifest_policy.type ? 5 : 4,
                                 default_policies);
        if (ret < 0)
            goto out_mem;

        pal_sec_info.pipe_prefix = remalloc(pipe_prefix, 9);
    } else {
        const struct graphene_user_policy default_policies[] = {
            { .type = GRAPHENE_NET_RULE,    .value = &mcast_rules[0], },
            { .type = GRAPHENE_NET_RULE,    .value = &mcast_rules[1], },
            manifest_policy,
        };

        ret = ioctl_set_graphene(&cfg, manifest_policy.type ? 3 : 2,
                                 default_policies);
        if (ret < 0)
            goto out_mem;
    }

    pal_config.manifest = manifest;
    _DkObjectClose(pal_config.manifest_handle);
    pal_config.manifest_handle = handle;

    free_config(&cfg);
out_mem:
    _DkStreamUnmap(cfg.raw_data, ALLOC_ALIGNUP(cfg.raw_size));
out:
    DkObjectClose(handle);
    return ret;
}

int _DkProcessSandboxCreate (const char * manifest, int flags)
{
    return set_graphene_task(manifest, flags);
}

static int proc_read (PAL_HANDLE handle, int offset, int count,
                          void * buffer)
{
    int bytes = INLINE_SYSCALL(read, 3, handle->process.stream_in, buffer,
                               count);

    if (IS_ERR(bytes))
        switch(ERRNO(bytes)) {
            case EWOULDBLOCK:
                return-PAL_ERROR_TRYAGAIN;
            case EINTR:
                return -PAL_ERROR_INTERRUPTED;
            default:
                return -PAL_ERROR_DENIED;
        }

    return bytes;
}

static int proc_write (PAL_HANDLE handle, int offset, int count,
                       const void * buffer)
{
    int bytes = INLINE_SYSCALL(write, 3, handle->process.stream_out, buffer,
                               count);

    if (IS_ERR(bytes))
        switch(ERRNO(bytes)) {
            case EWOULDBLOCK:
                handle->__in.flags &= ~WRITEABLE(1);
                return-PAL_ERROR_TRYAGAIN;
            case EINTR:
                return -PAL_ERROR_INTERRUPTED;
            default:
                return -PAL_ERROR_DENIED;
        }

    if (bytes == count)
        handle->__in.flags |= WRITEABLE(1);
    else
        handle->__in.flags &= ~WRITEABLE(1);

    return bytes;
}

static int proc_close (PAL_HANDLE handle)
{
    if (handle->process.stream_in != PAL_IDX_POISON) {
        INLINE_SYSCALL(close, 1, handle->process.stream_in);
        handle->process.stream_in = PAL_IDX_POISON;
    }

    if (handle->process.stream_out != PAL_IDX_POISON) {
        INLINE_SYSCALL(close, 1, handle->process.stream_out);
        handle->process.stream_out = PAL_IDX_POISON;
    }

    if (handle->process.cargo != PAL_IDX_POISON) {
        INLINE_SYSCALL(close, 1, handle->process.cargo);
        handle->process.cargo = PAL_IDX_POISON;
    }

    return 0;
}

static int proc_delete (PAL_HANDLE handle, int access)
{
    int shutdown;
    switch (access) {
        case 0:
            shutdown = SHUT_RDWR;
            break;
        case PAL_DELETE_RD:
            shutdown = SHUT_RD;
            break;
        case PAL_DELETE_WR:
            shutdown = SHUT_WR;
            break;
        default:
            return -PAL_ERROR_INVAL;
    }

    if (access != PAL_DELETE_WR &&
        handle->process.stream_in != PAL_IDX_POISON) {
        INLINE_SYSCALL(close, 1, handle->process.stream_in);
        handle->process.stream_in = PAL_IDX_POISON;
    }

    if (access != PAL_DELETE_RD &&
        handle->process.stream_out != PAL_IDX_POISON) {
        INLINE_SYSCALL(close, 1, handle->process.stream_out);
        handle->process.stream_out = PAL_IDX_POISON;
    }

    if (handle->process.cargo != PAL_IDX_POISON)
        INLINE_SYSCALL(shutdown, 2, handle->process.cargo, shutdown);

    return 0;
}

#ifndef FIONREAD
# define FIONREAD 0x541B
#endif

static int proc_attrquerybyhdl (PAL_HANDLE handle, PAL_STREAM_ATTR * attr)
{
    int ret, val;

    if (handle->process.stream_in == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    memset(attr, 0, sizeof(PAL_STREAM_ATTR));

    ret = INLINE_SYSCALL(ioctl, 3, handle->process.stream_in, FIONREAD, &val);
    if (!IS_ERR(ret))
        attr->size = val;

    attr->disconnected = handle->__in.flags & (ERROR(0)|ERROR(1));
    attr->readable = (attr->size > 0);
    attr->writeable = handle->__in.flags & WRITEABLE(1);
    attr->nonblocking = handle->process.nonblocking;
    return 0;
}

static int proc_attrsetbyhdl (PAL_HANDLE handle, PAL_STREAM_ATTR * attr)
{
    if (handle->process.stream_in == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    int ret;
    if (attr->nonblocking != handle->process.nonblocking) {
        ret = INLINE_SYSCALL(fcntl, 3, handle->process.stream_in, F_SETFL,
                             handle->process.nonblocking ? O_NONBLOCK : 0);

        if (IS_ERR(ret))
            return unix_to_pal_error(ERRNO(ret));

        handle->process.nonblocking = attr->nonblocking;
    }

    return 0;
}

struct handle_ops proc_ops = {
        .read           = &proc_read,
        .write          = &proc_write,
        .close          = &proc_close,
        .delete         = &proc_delete,
        .attrquerybyhdl = &proc_attrquerybyhdl,
        .attrsetbyhdl   = &proc_attrsetbyhdl,
    };
