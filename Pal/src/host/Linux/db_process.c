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

#include "api.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_rtld.h"
#include "pal_security.h"

typedef __kernel_pid_t pid_t;
#include <asm/errno.h>
#include <asm/fcntl.h>
#include <asm/poll.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

static inline int create_process_handle(PAL_HANDLE* parent, PAL_HANDLE* child) {
    PAL_HANDLE phdl = NULL;
    PAL_HANDLE chdl = NULL;
    int fds[2] = {-1, -1};
    int socktype = SOCK_STREAM | SOCK_CLOEXEC;
    int ret;

    ret = INLINE_SYSCALL(socketpair, 4, AF_UNIX, socktype, 0, fds);
    if (IS_ERR(ret)) {
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    phdl = malloc(HANDLE_SIZE(process));
    if (!phdl) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    SET_HANDLE_TYPE(phdl, process);
    HANDLE_HDR(phdl)->flags  |= RFD(0)|WFD(0);
    phdl->process.stream      = fds[0];
    phdl->process.pid         = linux_state.pid;
    phdl->process.nonblocking = PAL_FALSE;

    chdl = malloc(HANDLE_SIZE(process));
    if (!chdl) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    SET_HANDLE_TYPE(chdl, process);
    HANDLE_HDR(chdl)->flags |= RFD(0)|WFD(0);
    chdl->process.stream      = fds[1];
    chdl->process.pid         = 0; /* unknown yet */
    chdl->process.nonblocking = PAL_FALSE;

    *parent = phdl;
    *child  = chdl;
    ret = 0;
out:
    if (ret < 0) {
        free(phdl);
        free(chdl);
        if (fds[0] != -1)
            INLINE_SYSCALL(close, 1, fds[0]);
        if (fds[1] != -1)
            INLINE_SYSCALL(close, 1, fds[1]);
    }
    return ret;
}

struct proc_param {
    PAL_HANDLE parent;
    PAL_HANDLE exec;
    PAL_HANDLE manifest;
    const char** argv;
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

/*
 * vfork() shares stack between child and parent. Any stack modifications in
 * child are reflected in parent's stack. Compiler may unwittingly modify
 * child's stack for its own purposes and thus corrupt parent's stack
 * (e.g., GCC re-uses the same stack area for local vars with non-overlapping
 * lifetimes).
 * Introduce noinline function with stack area used only by child.
 * Make this function non-local to keep function signature.
 * NOTE: more tricks may be needed to prevent unexpected optimization for
 * future compiler.
 */
static int __attribute_noinline
child_process (struct proc_param * proc_param)
{
    int ret = ARCH_VFORK();
    if (ret)
        return ret;

    /* child */
    ret = INLINE_SYSCALL(dup2, 2, proc_param->parent->process.stream, PROC_INIT_FD);
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

failed:
    /* fail is it gets here */
    return -PAL_ERROR_DENIED;
}

int _DkProcessCreate (PAL_HANDLE * handle, const char * uri, const char ** args)
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

        /* If this process creation is for fork emulation,
         * map address of executable is already determined.
         * tell its address to forked process.
         */
        size_t len;
        const char * file_uri = URI_PREFIX_FILE;
        if (exec_map && exec_map->l_name &&
            (len = strlen(uri)) >= URI_PREFIX_FILE_LEN && !memcmp(uri, file_uri, URI_PREFIX_FILE_LEN) &&
            /* skip "file:"*/
            strlen(exec_map->l_name) == len - URI_PREFIX_FILE_LEN &&
            /* + 1 for lasting * NUL */
            !memcmp(exec_map->l_name, uri + URI_PREFIX_FILE_LEN, len - URI_PREFIX_FILE_LEN + 1))
            exec->file.map_start = (PAL_PTR)exec_map->l_map_start;
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

    size_t parent_datasz = 0, exec_datasz = 0, manifest_datasz = 0;
    void * parent_data = NULL;
    void * exec_data = NULL;
    void * manifest_data = NULL;

    ret = handle_serialize(parent_handle, &parent_data);
    if (ret < 0)
        goto out;
    parent_datasz = (size_t)ret;

    if (exec) {
        ret = handle_serialize(exec, &exec_data);
        if (ret < 0) {
            free(parent_data);
            goto out;
        }
        exec_datasz = (size_t)ret;
    }

    if (pal_state.manifest_handle) {
        ret = handle_serialize(pal_state.manifest_handle, &manifest_data);
        if (ret < 0) {
            free(parent_data);
            free(exec_data);
            goto out;
        }
        manifest_datasz = (size_t)ret;
    }

    size_t datasz = parent_datasz + exec_datasz + manifest_datasz;
    struct proc_args * proc_args = __alloca(sizeof(struct proc_args) + datasz);

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

    /* Child's signal handler may mess with parent's memory during vfork(),
     * so block signals
     */
    ret = block_async_signals(true);
    if (ret < 0)
        goto out;

    ret = child_process(&param);
    if (IS_ERR(ret)) {
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    proc_args->pal_sec.process_id = ret;
    child_handle->process.pid = ret;

    /* children unblock async signals by signal_setup() */
    ret = block_async_signals(false);
    if (ret < 0)
        goto out;

    /* step 4: send parameters over the process handle */

    ret = INLINE_SYSCALL(write, 3,
                         child_handle->process.stream,
                         proc_args,
                         sizeof(struct proc_args) + datasz);

    if (IS_ERR(ret) || (size_t)ret < sizeof(struct proc_args) + datasz) {
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
            INIT_FAIL(PAL_ERROR_DENIED, "communication fail with parent");

        /* in the first process */
        /* occupy PROC_INIT_FD so no one will use it */
        INLINE_SYSCALL(dup2, 2, 0, PROC_INIT_FD);
        return;
    }

    /* a child must have parent handle and an executable */
    if (!proc_args->parent_data_size)
        INIT_FAIL(PAL_ERROR_INVAL, "invalid process created");

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
        INIT_FAIL(PAL_ERROR_DENIED, "communication fail with parent");

    /* now deserialize the parent_handle */
    PAL_HANDLE parent = NULL;
    ret = handle_deserialize(&parent, data, proc_args->parent_data_size);
    if (ret < 0)
        INIT_FAIL(-ret, "cannot deseilaize parent process handle");
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
            INIT_FAIL(-ret, "cannot deserialize executable handle");

        data += proc_args->exec_data_size;
        *exec_handle = exec;
    }

    /* deserialize the manifest handle, if there is one */
    if (proc_args->manifest_data_size) {
        PAL_HANDLE manifest = NULL;

        ret = handle_deserialize(&manifest, data,
                                 proc_args->manifest_data_size);
        if (ret < 0)
            INIT_FAIL(-ret, "cannot deserialize manifest handle");

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

noreturn void _DkProcessExit (int exitcode)
{
    if (exitcode == PAL_WAIT_FOR_CHILDREN_EXIT) {
        /* this is a "temporary" process exiting after execve'ing a child process: it must still
         * be around until the child finally exits (because its parent in turn may wait on it) */
        int wstatus;
        int ret = INLINE_SYSCALL(wait4, 4, /*any child*/-1, &wstatus, /*options=*/0, /*rusage=*/NULL);
        if (IS_ERR(ret)) {
            /* it's too late to recover from errors, just set some reasonable exit code */
            exitcode = ECHILD;
        } else {
            /* Linux expects 0..127 for normal termination and 128..255 for signal termination */
            if (WIFEXITED(wstatus))
                exitcode = WEXITSTATUS(wstatus);
            else if (WIFSIGNALED(wstatus))
                exitcode = 128 + WTERMSIG(wstatus);
            else
                exitcode = ECHILD;
        }
    }

    INLINE_SYSCALL(exit_group, 1, exitcode);
    while (true) {
        /* nothing */;
    }
}

static int64_t proc_read (PAL_HANDLE handle, uint64_t offset, uint64_t count,
                      void * buffer)
{
    if (offset)
        return -PAL_ERROR_INVAL;

    int64_t bytes = INLINE_SYSCALL(read, 3, handle->process.stream, buffer, count);

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
    if (offset)
        return -PAL_ERROR_INVAL;

    int64_t bytes = INLINE_SYSCALL(write, 3, handle->process.stream, buffer, count);

    if (IS_ERR(bytes))
        switch(ERRNO(bytes)) {
            case EWOULDBLOCK:
                return -PAL_ERROR_TRYAGAIN;
            case EINTR:
                return -PAL_ERROR_INTERRUPTED;
            default:
                return -PAL_ERROR_DENIED;
        }

    assert(!IS_ERR(bytes));
    return bytes;
}

static int proc_close (PAL_HANDLE handle)
{
    if (handle->process.stream != PAL_IDX_POISON) {
        INLINE_SYSCALL(close, 1, handle->process.stream);
        handle->process.stream = PAL_IDX_POISON;
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

    if (handle->process.stream != PAL_IDX_POISON)
        INLINE_SYSCALL(shutdown, 2, handle->process.stream, shutdown);

    return 0;
}

static int proc_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    int ret;
    int val;

    if (handle->process.stream == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    attr->handle_type  = HANDLE_HDR(handle)->type;
    attr->nonblocking  = handle->process.nonblocking;
    attr->disconnected = HANDLE_HDR(handle)->flags & ERROR(0);

    /* get number of bytes available for reading */
    ret = INLINE_SYSCALL(ioctl, 3, handle->process.stream, FIONREAD, &val);
    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    attr->pending_size = val;

    /* query if there is data available for reading */
    struct pollfd pfd  = {.fd = handle->process.stream, .events = POLLIN | POLLOUT, .revents = 0};
    struct timespec tp = {0, 0};
    ret = INLINE_SYSCALL(ppoll, 5, &pfd, 1, &tp, NULL, 0);
    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    attr->readable = ret == 1 && (pfd.revents & (POLLIN | POLLERR | POLLHUP)) == POLLIN;
    attr->writable = ret == 1 && (pfd.revents & (POLLOUT | POLLERR | POLLHUP)) == POLLOUT;
    return 0;
}

static int proc_attrsetbyhdl (PAL_HANDLE handle, PAL_STREAM_ATTR * attr)
{
    if (handle->process.stream == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    int ret;
    if (attr->nonblocking != handle->process.nonblocking) {
        ret = INLINE_SYSCALL(fcntl, 3, handle->process.stream, F_SETFL,
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
