/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

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
#include <asm/errno.h>

#ifndef SEEK_SET
# define SEEK_SET 0
#endif

static inline int create_process_handle (PAL_HANDLE * parent,
                                         PAL_HANDLE * child)
{
    PAL_HANDLE phdl = NULL, chdl = NULL;
    int fds[6] = { -1, -1, -1, -1, -1, -1 };
    int ret;

    if (IS_ERR((ret = INLINE_SYSCALL(pipe2, 2, &fds[0], O_CLOEXEC))) ||
        IS_ERR((ret = INLINE_SYSCALL(pipe2, 2, &fds[2], O_CLOEXEC))) ||
        IS_ERR((ret = INLINE_SYSCALL(socketpair, 4, AF_UNIX,
                                     SOCK_STREAM|SOCK_CLOEXEC,
                                     0, &fds[4])))) {
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    int proc_fds[2][3] = {
        { fds[0], fds[3], fds[4] },
        { fds[2], fds[1], fds[5] },
    };

    phdl = malloc(HANDLE_SIZE(process));
    if (!phdl) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    SET_HANDLE_TYPE(phdl, process);
    HANDLE_HDR(phdl)->flags |= RFD(0)|WFD(1)|RFD(2)|WFD(2)|WRITEABLE(1)|WRITEABLE(2);
    phdl->process.stream_in   = proc_fds[0][0];
    phdl->process.stream_out  = proc_fds[0][1];
    phdl->process.cargo       = proc_fds[0][2];
    phdl->process.pid         = linux_state.pid;
    phdl->process.nonblocking = PAL_FALSE;

    chdl = malloc(HANDLE_SIZE(process));
    if (!chdl) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    SET_HANDLE_TYPE(chdl, process);
    HANDLE_HDR(chdl)->flags |= RFD(0)|WFD(1)|RFD(2)|WFD(2)|WRITEABLE(1)|WRITEABLE(2);
    chdl->process.stream_in   = proc_fds[1][0];
    chdl->process.stream_out  = proc_fds[1][1];
    chdl->process.cargo       = proc_fds[1][2];
    chdl->process.pid         = 0; /* unknown yet */
    chdl->process.nonblocking = PAL_FALSE;

    *parent = phdl;
    *child  = chdl;
    ret = 0;
out:
    if (ret < 0) {
        if (phdl)
            _DkObjectClose(phdl);
        if (chdl)
            _DkObjectClose(chdl);
        for (int i = 0 ; i < 6 ; i++)
            if (fds[i] != -1)
                INLINE_SYSCALL(close, 1, fds[i]);
    }
    return ret;
}

struct proc_param {
    PAL_HANDLE parent;
    PAL_HANDLE exec;
    PAL_HANDLE manifest;
    const char ** argv;
};

struct proc_args {
    PAL_NUM         parent_process_id;
    struct pal_sec  pal_sec;

#if PROFILING == 1
    unsigned long   process_create_time;
#endif
    unsigned long   memory_quota;

    unsigned int    parent_data_size;
    unsigned int    exec_data_size;
    unsigned int    manifest_data_size;
};

static int child_process (void * param)
{
    struct proc_param * proc_param = param;
    int ret;

    INLINE_SYSCALL(close, 1, PROC_INIT_FD);
    ret = INLINE_SYSCALL(dup2, 2, proc_param->parent->process.stream_in,
                         PROC_INIT_FD);
    if (IS_ERR(ret))
        goto failed;

    if (proc_param->parent)
        handle_set_cloexec(proc_param->parent,   false);
    if (proc_param->exec)
        handle_set_cloexec(proc_param->exec,     false);
    if (proc_param->manifest)
        handle_set_cloexec(proc_param->manifest, false);

    INLINE_SYSCALL(execve, 3, PAL_LOADER, proc_param->argv,
                   linux_state.environ);
    ret = -PAL_ERROR_DENIED;

failed:
    /* fail is it gets here */
    return ret;
}

int _DkProcessCreate (PAL_HANDLE * handle,
                      const char * uri, int flags, const char ** args)
{
    PAL_HANDLE exec = NULL;
    PAL_HANDLE parent_handle = NULL, child_handle = NULL;
    int ret;
#if PROFILING == 1
    unsigned long before_create = _DkSystemTimeQuery();
#endif

    /* step 1: open uri and check whether it is an executable */

    if (uri) {
        if ((ret = _DkStreamOpen(&exec, uri, PAL_ACCESS_RDONLY, 0, 0, 0)) < 0)
            return ret;

        if (check_elf_object(exec) < 0) {
            ret = -PAL_ERROR_INVAL;
            goto out;
        }
    }

    /* step 2: create parant and child process handle */

    struct proc_param param;
    ret = create_process_handle(&parent_handle, &child_handle);
    if (ret < 0)
        goto out;

    param.parent = parent_handle;
    param.exec = exec;
    param.manifest = pal_state.manifest_handle;

    /* step 3: compose process parameter */

    int parent_datasz = 0, exec_datasz = 0, manifest_datasz = 0;
    void * parent_data = NULL;
    void * exec_data = NULL;
    void * manifest_data = NULL;

    ret = handle_serialize(parent_handle, &parent_data);
    if (ret < 0)
        goto out;
    parent_datasz = ret;

    if (exec) {
        ret = handle_serialize(exec, &exec_data);
        if (ret < 0) {
            free(parent_data);
            goto out;
        }
        exec_datasz = ret;
    }

    if (pal_state.manifest_handle) {
        ret = handle_serialize(pal_state.manifest_handle, &manifest_data);
        if (ret < 0) {
            free(parent_data);
            free(exec_data);
            goto out;
        }
        manifest_datasz = ret;
    }

    unsigned int datasz = parent_datasz + exec_datasz + manifest_datasz;
    struct proc_args * proc_args =
            __alloca(sizeof(struct proc_args) + datasz);

    proc_args->parent_process_id = linux_state.parent_process_id;
    memcpy(&proc_args->pal_sec, &pal_sec, sizeof(struct pal_sec));
    proc_args->pal_sec._dl_debug_state = NULL;
    proc_args->pal_sec._r_debug = NULL;
    proc_args->memory_quota = linux_state.memory_quota;

    void * data = (void *) (proc_args + 1);

    memcpy(data, parent_data, parent_datasz);
    data += (proc_args->parent_data_size = parent_datasz);
    free(parent_data);

    if (exec_data) {
        memcpy(data, exec_data, exec_datasz);
        data += (proc_args->exec_data_size = exec_datasz);
        free(exec_data);
    } else {
        proc_args->exec_data_size = 0;
    }

    if (manifest_data) {
        memcpy(data, manifest_data, manifest_datasz);
        data += (proc_args->manifest_data_size = manifest_datasz);
        free(manifest_data);
    } else {
        proc_args->manifest_data_size = 0;
    }

    /* step 4: create a child thread which will execve in the future */

    /* the first arguement must be the PAL */
    int argc = 0;
    if (args)
        for (; args[argc] ; argc++);
    param.argv = __alloca(sizeof(const char *) * (argc + 2));
    param.argv[0] = PAL_LOADER;
    if (args)
        memcpy(&param.argv[1], args, sizeof(const char *) * argc);
    param.argv[argc + 1] = NULL;

#if PROFILING == 1
    proc_args->process_create_time = before_create;
#endif

    ret = ARCH_VFORK();
    int child_ret = 0;

    if (IS_ERR(ret)) {
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    if (!ret) {
        child_ret = child_process(&param);
        return 0;
    }

    if (child_ret < 0) {
        ret = child_ret;
        goto out;
    }

    proc_args->pal_sec.process_id = ret;
    child_handle->process.pid = ret;

    /* step 4: send parameters over the process handle */

    ret = INLINE_SYSCALL(write, 3,
                         child_handle->process.stream_out,
                         proc_args,
                         sizeof(struct proc_args) + datasz);

    if (IS_ERR(ret) ||
        ret < sizeof(struct proc_args) + datasz) {
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    *handle = child_handle;
    ret = 0;
out:
    if (parent_handle)
        _DkObjectClose(parent_handle);
    if (exec)
        _DkObjectClose(exec);
    if (ret < 0) {
        if (child_handle)
            _DkObjectClose(child_handle);
    }
    return ret;
}

void init_child_process (PAL_HANDLE * parent_handle,
                         PAL_HANDLE * exec_handle,
                         PAL_HANDLE * manifest_handle)
{
    int ret = 0;

    /* try to do a very large reading, so it doesn't have to be read for the
       second time */
    struct proc_args * proc_args = __alloca(sizeof(struct proc_args));
    struct proc_args * new_proc_args;

    int bytes = INLINE_SYSCALL(read, 3, PROC_INIT_FD, proc_args,
                               sizeof(*proc_args));

    if (IS_ERR(bytes)) {
        if (ERRNO(bytes) != EBADF)
            init_fail(PAL_ERROR_DENIED, "communication fail with parent");

        /* in the first process */
        /* occupy PROC_INIT_FD so no one will use it */
        INLINE_SYSCALL(dup2, 2, 0, PROC_INIT_FD);
        return;
    }

    /* a child must have parent handle and an executable */
    if (!proc_args->parent_data_size)
        init_fail(PAL_ERROR_INVAL, "invalid process created");

    int datasz = proc_args->parent_data_size + proc_args->exec_data_size +
                 proc_args->manifest_data_size;

    if (!datasz)
        goto no_data;

    new_proc_args = __alloca(sizeof(*proc_args) + datasz);
    memcpy(new_proc_args, proc_args, sizeof(*proc_args));
    proc_args = new_proc_args;
    void * data = (void *) (proc_args + 1);

    bytes = INLINE_SYSCALL(read, 3, PROC_INIT_FD, data, datasz);
    if (IS_ERR(bytes))
        init_fail(PAL_ERROR_DENIED, "communication fail with parent");

    /* now deserialize the parent_handle */
    PAL_HANDLE parent = NULL;
    ret = handle_deserialize(&parent, data, proc_args->parent_data_size);
    if (ret < 0)
        init_fail(-ret, "cannot deseilaize parent process handle");
    data += proc_args->parent_data_size;
    *parent_handle = parent;

    /* occupy PROC_INIT_FD so no one will use it */
    INLINE_SYSCALL(dup2, 2, 0, PROC_INIT_FD);

    /* deserialize the executable handle */
    if (proc_args->exec_data_size) {
        PAL_HANDLE exec = NULL;

        ret = handle_deserialize(&exec, data,
                                 proc_args->exec_data_size);
        if (ret < 0)
            init_fail(-ret, "cannot deserialize executable handle");

        data += proc_args->exec_data_size;
        *exec_handle = exec;
    }

    /* deserialize the manifest handle, if there is one */
    if (proc_args->manifest_data_size) {
        PAL_HANDLE manifest = NULL;

        ret = handle_deserialize(&manifest, data,
                                 proc_args->manifest_data_size);
        if (ret < 0)
            init_fail(-ret, "cannot deserialize manifest handle");

        data += proc_args->manifest_data_size;
        *manifest_handle = manifest;
    }

no_data:
    linux_state.parent_process_id = proc_args->parent_process_id;
    linux_state.memory_quota = proc_args->memory_quota;
#if PROFILING == 1
    pal_state.process_create_time = proc_args->process_create_time;
#endif
    memcpy(&pal_sec, &proc_args->pal_sec, sizeof(struct pal_sec));
}

void _DkProcessExit (int exitcode)
{
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
    size_t size = attr.pending_size;

    if ((ret = _DkStreamMap(handle, &addr, PAL_PROT_READ, 0,
                            ALLOC_ALIGNUP(size))) < 0)
        goto out;

    struct config_store sandbox_config;
    sandbox_config.raw_data = addr;
    sandbox_config.raw_size = size;
    sandbox_config.malloc = malloc;
    sandbox_config.free = free;

    if ((ret = read_config(&sandbox_config, NULL, NULL)) < 0)
        goto out_mem;

    struct graphene_user_policy policies[5], * p = policies;

    if (strpartcmp_static(uri, "file:")) {
        p->type  = GRAPHENE_FS_PATH | GRAPHENE_FS_READ;
        p->value = &uri[5];
        p++;
    }

    if (flags & PAL_SANDBOX_PIPE) {
        p->type  = GRAPHENE_UNIX_PREFIX;
        p->value = &pal_sec.pipe_prefix_id;
        p++;

        p->type  = GRAPHENE_MCAST_PORT;
        p->value = &pal_sec.mcast_port;
        p++;
    }

    p->type  = GRAPHENE_FS_PATH | GRAPHENE_FS_READ;
    p->value = "/proc/meminfo";
    p++;

    ret = ioctl_set_graphene(&sandbox_config, p - policies, policies);
    if (ret < 0)
        goto out_mem;

    pal_state.manifest = uri;
    _DkObjectClose(pal_state.manifest_handle);
    pal_state.manifest_handle = handle;

    free_config(&sandbox_config);
out_mem:
    _DkStreamUnmap(sandbox_config.raw_data,
                   ALLOC_ALIGNUP(sandbox_config.raw_size));
out:
    _DkObjectClose(handle);
    return ret;
}

int _DkProcessSandboxCreate (const char * manifest, int flags)
{
    return set_graphene_task(manifest, flags);
}

static int64_t proc_read (PAL_HANDLE handle, uint64_t offset, uint64_t count,
                      void * buffer)
{
    int64_t bytes = INLINE_SYSCALL(read, 3, handle->process.stream_in, buffer,
                                   count);

    if (IS_ERR(bytes))
        switch(ERRNO(bytes)) {
            case EWOULDBLOCK:
                return -PAL_ERROR_TRYAGAIN;
            case EINTR:
                return -PAL_ERROR_INTERRUPTED;
            default:
                return -PAL_ERROR_DENIED;
        }

    return bytes;
}

static int64_t proc_write (PAL_HANDLE handle, uint64_t offset, uint64_t count,
                       const void * buffer)
{
    int64_t bytes = INLINE_SYSCALL(write, 3, handle->process.stream_out, buffer,
                                   count);

    if (IS_ERR(bytes))
        switch(ERRNO(bytes)) {
            case EWOULDBLOCK:
                HANDLE_HDR(handle)->flags &= ~WRITEABLE(1);
                return -PAL_ERROR_TRYAGAIN;
            case EINTR:
                return -PAL_ERROR_INTERRUPTED;
            default:
                return -PAL_ERROR_DENIED;
        }

    if (bytes == count)
        HANDLE_HDR(handle)->flags |= WRITEABLE(1);
    else
        HANDLE_HDR(handle)->flags &= ~WRITEABLE(1);

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

    ret = INLINE_SYSCALL(ioctl, 3, handle->process.stream_in, FIONREAD, &val);
    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    attr->handle_type  = pal_type_process;
    attr->nonblocking  = handle->process.nonblocking;
    attr->disconnected = HANDLE_HDR(handle)->flags & (ERROR(0)|ERROR(1));
    attr->readable     = !!val;
    attr->writeable    = HANDLE_HDR(handle)->flags & WRITEABLE(1);
    attr->runnable     = PAL_FALSE;
    attr->pending_size = val;

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
