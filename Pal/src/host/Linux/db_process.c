/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This source file contains functions to create a child process and terminate the running process.
 * Child does not inherit any objects or memory from its parent process. A parent process may not
 * modify the execution of its children. It can wait for a child to exit using its handle. Also,
 * parent and child may communicate through I/O streams provided by the parent to the child at
 * creation.
 */

#include <asm/errno.h>
#include <asm/fcntl.h>
#include <asm/ioctls.h>
#include <asm/poll.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/types.h>
#include <sys/socket.h>

#include "api.h"
#include "linux_utils.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_rtld.h"
#include "pal_security.h"

/*
 * This needs to be included here because it conflicts with sigset.h included in pal_linux.
 * TODO: Make sure we define WIFEXITED() etc. and remove this.
 */
#include <sys/wait.h>

extern char* g_pal_loader_path;
extern char* g_libpal_path;

static inline int create_process_handle(PAL_HANDLE* parent, PAL_HANDLE* child) {
    PAL_HANDLE phdl = NULL;
    PAL_HANDLE chdl = NULL;
    int fds[2] = {-1, -1};
    int socktype = SOCK_STREAM | SOCK_CLOEXEC;
    int ret;

    ret = INLINE_SYSCALL(socketpair, 4, AF_UNIX, socktype, 0, fds);
    if (ret < 0) {
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    phdl = malloc(HANDLE_SIZE(process));
    if (!phdl) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    SET_HANDLE_TYPE(phdl, process);
    HANDLE_HDR(phdl)->flags  |= RFD(0) | WFD(0);
    phdl->process.stream      = fds[0];
    phdl->process.pid         = g_linux_state.pid;
    phdl->process.nonblocking = PAL_FALSE;

    chdl = malloc(HANDLE_SIZE(process));
    if (!chdl) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    SET_HANDLE_TYPE(chdl, process);
    HANDLE_HDR(chdl)->flags  |= RFD(0) | WFD(0);
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
    const char** argv;
};

struct proc_args {
    PAL_NUM         parent_process_id;
    struct pal_sec  pal_sec;

    unsigned long   memory_quota;

    size_t parent_data_size;
    size_t manifest_data_size;
    size_t exec_uri_size;
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
static int __attribute_noinline child_process(struct proc_param* proc_param) {
    int ret = ARCH_VFORK();
    if (ret)
        return ret;

    /* child */
    if (proc_param->parent)
        handle_set_cloexec(proc_param->parent, false);
    if (proc_param->exec)
        handle_set_cloexec(proc_param->exec, false);

    int res = INLINE_SYSCALL(execve, 3, g_pal_loader_path, proc_param->argv,
                             g_linux_state.host_environ);
    /* execve failed, but we're after vfork, so we can't do anything more than just exit */
    INLINE_SYSCALL(exit_group, 1, -res);
    die_or_inf_loop();
}

int _DkProcessCreate(PAL_HANDLE* handle, const char* exec_uri, const char** args) {
    PAL_HANDLE exec = NULL;
    PAL_HANDLE parent_handle = NULL;
    PAL_HANDLE child_handle = NULL;
    struct proc_args* proc_args = NULL;
    void* parent_data = NULL;
    void* exec_data = NULL;
    int ret;

    assert(exec_uri);

    /* step 1: open exec_uri and check whether it is an executable */

    if ((ret = _DkStreamOpen(&exec, exec_uri, PAL_ACCESS_RDONLY, 0, 0, 0)) < 0)
        return ret;

    if (!is_elf_object(exec)) {
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    /* If this process creation is for fork emulation, map address of executable is already
     * determined. Tell its address to the forked process. */
    if (g_exec_map && g_exec_map->l_name && strstartswith(exec_uri, URI_PREFIX_FILE) &&
            !strcmp(g_exec_map->l_name, exec_uri + URI_PREFIX_FILE_LEN)) {
        exec->file.map_start = (PAL_PTR)g_exec_map->l_map_start;
    }

    /* step 2: create parent and child process handle */

    struct proc_param param;
    ret = create_process_handle(&parent_handle, &child_handle);
    if (ret < 0)
        goto out;

    param.parent   = parent_handle;
    param.exec     = exec;

    /* step 3: compose process parameters */

    size_t parent_data_size = 0;
    size_t manifest_data_size = 0;
    size_t exec_uri_size = strlen(exec_uri);

    ret = handle_serialize(parent_handle, &parent_data);
    if (ret < 0)
        goto out;
    parent_data_size = (size_t)ret;

    manifest_data_size = strlen(g_pal_state.raw_manifest_data);

    size_t data_size = parent_data_size + manifest_data_size + exec_uri_size;
    proc_args = malloc(sizeof(struct proc_args) + data_size);
    if (!proc_args) {
        ret = -ENOMEM;
        goto out;
    }

    proc_args->parent_process_id = g_linux_state.parent_process_id;
    memcpy(&proc_args->pal_sec, &g_pal_sec, sizeof(struct pal_sec));
    proc_args->memory_quota            = g_linux_state.memory_quota;

    char* data = (char*)(proc_args + 1);

    memcpy(data, parent_data, parent_data_size);
    proc_args->parent_data_size = parent_data_size;
    data += parent_data_size;

    memcpy(data, g_pal_state.raw_manifest_data, manifest_data_size);
    proc_args->manifest_data_size = manifest_data_size;
    data += manifest_data_size;

    memcpy(data, exec_uri, exec_uri_size);
    proc_args->exec_uri_size = exec_uri_size;
    data += exec_uri_size;

    /* step 4: create a child thread which will execve in the future */

    /* the first argument must be the PAL */
    int argc = 0;
    if (args)
        for (; args[argc]; argc++)
            ;
    param.argv = __alloca(sizeof(const char*) * (argc + 5));
    param.argv[0] = g_pal_loader_path;
    param.argv[1] = g_libpal_path;
    param.argv[2] = "child";
    char parent_fd_str[16];
    snprintf(parent_fd_str, sizeof(parent_fd_str), "%u", parent_handle->process.stream);
    param.argv[3] = parent_fd_str;
    if (args)
        memcpy(&param.argv[4], args, sizeof(const char*) * argc);
    param.argv[argc + 4] = NULL;

    /* Child's signal handler may mess with parent's memory during vfork(),
     * so block signals
     */
    ret = block_async_signals(true);
    if (ret < 0)
        goto out;

    ret = child_process(&param);
    if (ret < 0) {
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

    ret = write_all(child_handle->process.stream, proc_args, sizeof(struct proc_args) + data_size);
    if (ret < 0) {
        ret = unix_to_pal_error(ret);
        goto out;
    }

    *handle = child_handle;
    ret = 0;
out:
    free(parent_data);
    free(exec_data);
    free(proc_args);
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

void init_child_process(int parent_pipe_fd, PAL_HANDLE* parent_handle, char** exec_uri_out,
                        char** manifest_out) {
    int ret = 0;

    struct proc_args proc_args;

    ret = read_all(parent_pipe_fd, &proc_args, sizeof(proc_args));
    if (ret < 0) {
        ret = unix_to_pal_error(ret);
        INIT_FAIL(-ret, "communication with parent failed");
    }

    /* a child must have parent handle and an executable */
    if (!proc_args.parent_data_size)
        INIT_FAIL(PAL_ERROR_INVAL, "invalid process created");

    size_t data_size = proc_args.parent_data_size
                       + proc_args.manifest_data_size + proc_args.exec_uri_size;
    char* data = malloc(data_size);
    if (!data)
        INIT_FAIL(PAL_ERROR_NOMEM, "Out of memory");

    ret = read_all(parent_pipe_fd, data, data_size);
    if (ret < 0) {
        ret = unix_to_pal_error(ret);
        INIT_FAIL(-ret, "communication with parent failed");
    }

    /* now deserialize the parent_handle */
    PAL_HANDLE parent = NULL;
    char* data_iter = data;
    ret = handle_deserialize(&parent, data_iter, proc_args.parent_data_size);
    if (ret < 0)
        INIT_FAIL(-ret, "cannot deserialize parent process handle");
    data_iter += proc_args.parent_data_size;
    *parent_handle = parent;

    char* manifest = malloc(proc_args.manifest_data_size + 1);
    if (!manifest)
        INIT_FAIL(PAL_ERROR_NOMEM, "Out of memory");
    memcpy(manifest, data_iter, proc_args.manifest_data_size);
    manifest[proc_args.manifest_data_size] = '\0';
    data_iter += proc_args.manifest_data_size;

    char* exec_uri = malloc(proc_args.exec_uri_size + 1);
    if (!exec_uri)
        INIT_FAIL(PAL_ERROR_NOMEM, "Out of memory");
    memcpy(exec_uri, data_iter, proc_args.exec_uri_size);
    exec_uri[proc_args.exec_uri_size] = '\0';
    data_iter += proc_args.exec_uri_size;

    g_linux_state.parent_process_id = proc_args.parent_process_id;
    g_linux_state.memory_quota = proc_args.memory_quota;
    memcpy(&g_pal_sec, &proc_args.pal_sec, sizeof(struct pal_sec));

    *exec_uri_out = exec_uri;
    *manifest_out = manifest;
    free(data);
}

noreturn void _DkProcessExit(int exitcode) {
    INLINE_SYSCALL(exit_group, 1, exitcode);
    die_or_inf_loop();
}

static int64_t proc_read(PAL_HANDLE handle, uint64_t offset, uint64_t count, void* buffer) {
    if (offset)
        return -PAL_ERROR_INVAL;

    int64_t bytes = INLINE_SYSCALL(read, 3, handle->process.stream, buffer, count);

    if (bytes < 0)
        switch (bytes) {
            case -EWOULDBLOCK:
                return -PAL_ERROR_TRYAGAIN;
            case -EINTR:
                return -PAL_ERROR_INTERRUPTED;
            default:
                return -PAL_ERROR_DENIED;
        }

    return bytes;
}

static int64_t proc_write(PAL_HANDLE handle, uint64_t offset, uint64_t count, const void* buffer) {
    if (offset)
        return -PAL_ERROR_INVAL;

    int64_t bytes = INLINE_SYSCALL(write, 3, handle->process.stream, buffer, count);

    if (bytes < 0)
        switch (bytes) {
            case -EWOULDBLOCK:
                return -PAL_ERROR_TRYAGAIN;
            case -EINTR:
                return -PAL_ERROR_INTERRUPTED;
            default:
                return -PAL_ERROR_DENIED;
        }

    return bytes;
}

static int proc_close(PAL_HANDLE handle) {
    if (handle->process.stream != PAL_IDX_POISON) {
        INLINE_SYSCALL(close, 1, handle->process.stream);
        handle->process.stream = PAL_IDX_POISON;
    }

    return 0;
}

static int proc_delete(PAL_HANDLE handle, int access) {
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
    if (ret < 0)
        return unix_to_pal_error(ret);

    attr->pending_size = val;

    /* query if there is data available for reading */
    struct pollfd pfd  = {.fd = handle->process.stream, .events = POLLIN | POLLOUT, .revents = 0};
    struct timespec tp = {0, 0};
    ret = INLINE_SYSCALL(ppoll, 5, &pfd, 1, &tp, NULL, 0);
    if (ret < 0)
        return unix_to_pal_error(ret);

    attr->readable = ret == 1 && (pfd.revents & (POLLIN | POLLERR | POLLHUP)) == POLLIN;
    attr->writable = ret == 1 && (pfd.revents & (POLLOUT | POLLERR | POLLHUP)) == POLLOUT;
    return 0;
}

static int proc_attrsetbyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    if (handle->process.stream == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    int ret;
    if (attr->nonblocking != handle->process.nonblocking) {
        ret = INLINE_SYSCALL(fcntl, 3, handle->process.stream, F_SETFL,
                             handle->process.nonblocking ? O_NONBLOCK : 0);

        if (ret < 0)
            return unix_to_pal_error(ret);

        handle->process.nonblocking = attr->nonblocking;
    }

    return 0;
}

struct handle_ops g_proc_ops = {
    .read           = &proc_read,
    .write          = &proc_write,
    .close          = &proc_close,
    .delete         = &proc_delete,
    .attrquerybyhdl = &proc_attrquerybyhdl,
    .attrsetbyhdl   = &proc_attrsetbyhdl,
};
