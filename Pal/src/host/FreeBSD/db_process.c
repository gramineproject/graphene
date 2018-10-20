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
#include "pal_freebsd_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_freebsd.h"
#include "pal_debug.h"
#include "pal_error.h"
#include "pal_security.h"
#include "api.h"

#include <sched.h>
#include <sys/types.h>
typedef __kernel_pid_t pid_t;
#include <fcntl.h>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/filio.h>
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
    phdl->hdr.flags |= RFD(0)|WFD(1)|RFD(2)|WFD(2)|WRITEABLE(1)|WRITEABLE(2);
    phdl->process.stream_in   = proc_fds[0][0];
    phdl->process.stream_out  = proc_fds[0][1];
    phdl->process.cargo       = proc_fds[0][2];
    phdl->process.pid         = bsd_state.pid;
    phdl->process.nonblocking = PAL_FALSE;

    chdl = malloc(HANDLE_SIZE(process));
    if (!chdl) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    SET_HANDLE_TYPE(chdl, process);
    chdl->hdr.flags |= RFD(0)|WFD(1)|RFD(2)|WFD(2)|WRITEABLE(1)|WRITEABLE(2);
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
    PAL_NUM parent_process_id;
    struct pal_sec  pal_sec;
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

    handle_set_cloexec(proc_param->parent, false);
    if (proc_param->exec)
        handle_set_cloexec(proc_param->exec, false);
    if (proc_param->manifest)
        handle_set_cloexec(proc_param->manifest, false);

    INLINE_SYSCALL(execve, 3, PAL_LOADER, proc_param->argv, NULL);

failed:
    /* fail is it gets here */
    _DkThreadExit();
    return 0;
}

int _DkProcessCreate (PAL_HANDLE * handle,
                      const char * uri, int flags, const char ** args)
{
    PAL_HANDLE exec = NULL;
    PAL_HANDLE parent_handle = NULL, child_handle = NULL;
    int ret;

    /* step 1: open uri and check whether it is an executable */

    if (uri) {
        if ((ret = _DkStreamOpen(&exec, uri, PAL_ACCESS_RDONLY, 0, 0, 0)) < 0)
            return ret;

        handle_set_cloexec(exec, true);
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

    proc_args->parent_process_id = bsd_state.parent_pid;
    memcpy(&proc_args->pal_sec, &pal_sec, sizeof(struct pal_sec));
    proc_args->pal_sec.r_debug_state = NULL;
    proc_args->pal_sec.r_debug = NULL;
    proc_args->memory_quota = bsd_state.memory_quota;

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

    ret = INLINE_SYSCALL(vfork, 0);

    if (IS_ERR(ret)) {
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    if (!ret) {
        child_process(&param);
        return 0;
    }

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
    if (ret < 0) {
        if (child_handle)
            _DkObjectClose(child_handle);
        if (exec)
            _DkObjectClose(exec);
    }
    return ret;
}

#define LARGE_PROC_ARGS 4096

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
    bsd_state.memory_quota = proc_args->memory_quota;
    memcpy(&pal_sec, &proc_args->pal_sec, sizeof(struct pal_sec));
}

void _DkProcessExit (int exitcode)
{
    INLINE_SYSCALL(exit, 1, exitcode);
}

int _DkProcessSandboxCreate (const char * manifest, int flags)
{
    PAL_HANDLE handle = NULL;
    _DkStreamOpen(&handle, manifest, PAL_ACCESS_RDONLY, 0, 0, 0);
    pal_state.manifest_handle = handle;
    pal_state.manifest = manifest;
    return -PAL_ERROR_NOTIMPLEMENTED;
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
                handle->hdr.flags &= ~WRITEABLE(1);
                return-PAL_ERROR_TRYAGAIN;
            case EINTR:
                return -PAL_ERROR_INTERRUPTED;
            default:
                return -PAL_ERROR_DENIED;
        }

    if (bytes == count)
        handle->hdr.flags |= WRITEABLE(1);
    else
        handle->hdr.flags &= ~WRITEABLE(1);

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
    attr->disconnected = handle->hdr.flags & (ERROR(0)|ERROR(1));
    attr->readable     = !!val;
    attr->writeable    = handle->hdr.flags & WRITEABLE(1);
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
