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
#include <linux/fs.h>

#include "pal_linux.h"
#include "pal_rtld.h"
#include "sgx_enclave.h"
#include "sgx_internal.h"
#include "sgx_tls.h"

extern char* g_pal_loader_path;
extern char* g_libpal_path;

struct proc_args {
    PAL_SEC_STR  exec_name;
    unsigned int instance_id;
    unsigned int parent_process_id;
    int          stream_fd;
    PAL_SEC_STR  pipe_prefix;
    size_t       manifest_size; // manifest will follow this struct on the pipe.
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
static int __attribute_noinline vfork_exec(int parent_stream, const char** argv) {
    int ret = ARCH_VFORK();
    if (ret)
        return ret;

    /* child: close parent's FDs and execve */
    INLINE_SYSCALL(close, 1, parent_stream);

    extern char** environ;
    ret = INLINE_SYSCALL(execve, 3, g_pal_loader_path, argv, environ);

    /* shouldn't get to here */
    SGX_DBG(DBG_E, "unexpected failure of execve\n");
    __asm__ volatile("hlt");
    return 0;
}

int sgx_create_process(const char* uri, size_t nargs, const char** args, int* stream_fd,
                       const char* manifest) {
    int ret, rete, child;
    int fds[2] = {-1, -1};

    int socktype = SOCK_STREAM;
    if (IS_ERR((ret = INLINE_SYSCALL(socketpair, 4, AF_UNIX, socktype, 0, fds))))
        goto out;

    const char** argv = __alloca(sizeof(const char*) * (nargs + 5));
    argv[0] = g_pal_loader_path;
    argv[1] = g_libpal_path;
    argv[2] = "child";
    char parent_fd_str[16];
    snprintf(parent_fd_str, sizeof(parent_fd_str), "%u", fds[0]);
    argv[3] = parent_fd_str;
    memcpy(argv + 4, args, sizeof(const char*) * nargs);
    argv[nargs + 4] = NULL;

    /* child's signal handler may mess with parent's memory during vfork(), so block signals */
    ret = block_async_signals(true);
    if (ret < 0) {
        ret = -ret;
        goto out;
    }

    ret = vfork_exec(/*parent_stream=*/fds[1], argv);
    if (IS_ERR(ret))
        goto out;

    /* parent continues here */
    child = ret;

    /* children unblock async signals by sgx_signal_setup() */
    ret = block_async_signals(false);
    if (ret < 0) {
        ret = -ret;
        goto out;
    }

    INLINE_SYSCALL(close, 1, fds[0]); /* child stream */

    struct pal_sec* pal_sec = &g_pal_enclave.pal_sec;
    struct proc_args proc_args;
    memcpy(proc_args.exec_name, uri, sizeof(PAL_SEC_STR));
    proc_args.instance_id       = pal_sec->instance_id;
    proc_args.parent_process_id = pal_sec->pid;
    proc_args.stream_fd         = fds[0];
    proc_args.manifest_size     = strlen(manifest);
    memcpy(proc_args.pipe_prefix, pal_sec->pipe_prefix, sizeof(PAL_SEC_STR));

    ret = INLINE_SYSCALL(write, 3, fds[1], &proc_args, sizeof(struct proc_args));
    if (IS_ERR(ret) || (size_t)ret != sizeof(struct proc_args)) {
        ret = IS_ERR(ret) ? ret : -EINTR;
        goto out;
    }

    ret = INLINE_SYSCALL(write, 3, fds[1], manifest, proc_args.manifest_size);
    if (IS_ERR(ret) || (size_t)ret != proc_args.manifest_size) {
        ret = IS_ERR(ret) ? ret : -EINTR;
        goto out;
    }

    ret = INLINE_SYSCALL(read, 3, fds[1], &rete, sizeof(rete));
    if (IS_ERR(ret) || (size_t)ret != sizeof(rete)) {
        ret = IS_ERR(ret) ? ret : -EINTR;
        goto out;
    }

    if (IS_ERR(rete)) {
        ret = rete;
        goto out;
    }

    INLINE_SYSCALL(fcntl, 3, fds[1], F_SETFD, FD_CLOEXEC);

    if (stream_fd)
        *stream_fd = fds[1];

    ret = child;
out:
    if (IS_ERR(ret)) {
        if (fds[0] >= 0)
            INLINE_SYSCALL(close, 1, fds[0]);
        if (fds[1] >= 0)
            INLINE_SYSCALL(close, 1, fds[1]);
    }

    return ret;
}

int sgx_init_child_process(int parent_pipe_fd, struct pal_sec* pal_sec, char** manifest_out) {
    int ret;
    struct proc_args proc_args;
    long bytes_read, bytes_written;
    char* manifest = NULL;

    bytes_read = INLINE_SYSCALL(read, 3, parent_pipe_fd, &proc_args, sizeof(struct proc_args));
    if (IS_ERR(bytes_read) || bytes_read != sizeof(struct proc_args)) {
        ret = IS_ERR(bytes_read) ? bytes_read : -EINTR;
        goto out;
    }

    manifest = malloc(proc_args.manifest_size + 1);
    if (!manifest) {
        ret = -ENOMEM;
        goto out;
    }

    bytes_read = INLINE_SYSCALL(read, 3, parent_pipe_fd, manifest, proc_args.manifest_size);
    if (IS_ERR(bytes_read)) {
        ret = IS_ERR(bytes_read) ? bytes_read : -EINTR;
        goto out;
    }
    manifest[proc_args.manifest_size] = '\0';

    int child_status = 0;
    bytes_written = INLINE_SYSCALL(write, 3, parent_pipe_fd, &child_status, sizeof(int));
    if (IS_ERR(bytes_written)) {
        ret = IS_ERR(bytes_written) ? bytes_written : -EINTR;
        goto out;
    }

    memcpy(pal_sec->exec_name, proc_args.exec_name, sizeof(PAL_SEC_STR));
    pal_sec->instance_id = proc_args.instance_id;
    pal_sec->ppid        = proc_args.parent_process_id;
    pal_sec->stream_fd   = proc_args.stream_fd;
    memcpy(pal_sec->pipe_prefix, proc_args.pipe_prefix, sizeof(PAL_SEC_STR));

    *manifest_out = manifest;
    ret = 0;
out:
    if (ret < 0)
        free(manifest);
    return ret;
}
