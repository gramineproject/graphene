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

#include <pal_linux.h>
#include <pal_rtld.h>
#include "sgx_internal.h"
#include "sgx_tls.h"
#include "sgx_enclave.h"

#include <asm/fcntl.h>
#include <asm/errno.h>
#include <linux/fs.h>

#define PAL_LOADER RUNTIME_FILE("pal-Linux-SGX")

struct proc_args {
    PAL_SEC_STR     exec_name;
    unsigned int    instance_id;
    unsigned int    parent_process_id;
    int             stream_fd;
    PAL_SEC_STR     pipe_prefix;
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
vfork_exec(int child_stream, int parent_stream, const char** argv) {
    int ret = ARCH_VFORK();
    if (ret)
        return ret;

    /* child: close parent's FDs, rewire child stream to init FD, and execve */
    INLINE_SYSCALL(close, 1, parent_stream);

    ret = INLINE_SYSCALL(dup2, 2, child_stream, PROC_INIT_FD);
    if (!IS_ERR(ret)) {
        extern char** environ;
        ret = INLINE_SYSCALL(execve, 3, PAL_LOADER, argv, environ);

        /* shouldn't get to here */
        SGX_DBG(DBG_E, "unexpected failure of new process\n");
    }
    __asm__ volatile ("hlt");
    return 0;
}

int sgx_create_process(const char* uri, int nargs, const char** args, int* stream_fd) {
    int ret, rete, child;
    int fds[2] = {-1, -1};

    if (!uri || !strstartswith_static(uri, URI_PREFIX_FILE))
        return -EINVAL;

    int socktype = SOCK_STREAM;
    if (IS_ERR((ret = INLINE_SYSCALL(socketpair, 4, AF_UNIX, socktype, 0, fds))))
        goto out;

    const char ** argv = __alloca(sizeof(const char *) * (nargs + 2));
    argv[0] = PAL_LOADER;
    memcpy(argv + 1, args, sizeof(const char *) * nargs);
    argv[nargs + 1] = NULL;

    /* child's signal handler may mess with parent's memory during vfork(), so block signals */
    ret = block_async_signals(true);
    if (ret < 0) {
        ret = -ret;
        goto out;
    }

    ret = vfork_exec(/*child_stream=*/fds[0], /*parent_stream=*/fds[1], argv);
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

    struct pal_sec * pal_sec = &pal_enclave.pal_sec;
    struct proc_args proc_args;
    memcpy(proc_args.exec_name, uri, sizeof(PAL_SEC_STR));
    proc_args.instance_id       = pal_sec->instance_id;
    proc_args.parent_process_id = pal_sec->pid;
    proc_args.stream_fd         = fds[0];
    memcpy(proc_args.pipe_prefix, pal_sec->pipe_prefix, sizeof(PAL_SEC_STR));

    ret = INLINE_SYSCALL(write, 3, fds[1], &proc_args, sizeof(struct proc_args));
    if (IS_ERR(ret) || (size_t)ret < sizeof(struct proc_args)) {
        ret = -EPERM;
        goto out;
    }

    ret = INLINE_SYSCALL(read, 3, fds[1], &rete, sizeof(int));
    if (IS_ERR(ret) || (size_t)ret < sizeof(int)) {
        ret = -EPERM;
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

int sgx_init_child_process (struct pal_sec * pal_sec)
{
    struct proc_args proc_args;

    int ret = INLINE_SYSCALL(read, 3, PROC_INIT_FD, &proc_args, sizeof(struct proc_args));
    if (IS_ERR(ret)) {
        if (ERRNO(ret) == EBADF)
            return 0;
        return ret;
    }

    int child_status = 0;
    ret = INLINE_SYSCALL(write, 3, PROC_INIT_FD, &child_status, sizeof(int));
    if (IS_ERR(ret))
        return ret;

    memcpy(pal_sec->exec_name, proc_args.exec_name, sizeof(PAL_SEC_STR));
    pal_sec->instance_id   = proc_args.instance_id;
    pal_sec->ppid          = proc_args.parent_process_id;
    pal_sec->stream_fd     = proc_args.stream_fd;
    memcpy(pal_sec->pipe_prefix, proc_args.pipe_prefix, sizeof(PAL_SEC_STR));

    return 1;
}
