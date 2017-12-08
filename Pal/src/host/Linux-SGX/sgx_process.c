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
    unsigned int    proc_fds[3];
    PAL_SEC_STR     pipe_prefix;
    unsigned int    mcast_port;
};

int sgx_create_process (const char * uri, int nargs, const char ** args,
                        int * retfds)
{
    int ret, rete, child;
    int fds[6] = { -1, -1, -1, -1, -1, -1 };

    if (!uri || !strpartcmp_static(uri, "file:"))
        return -PAL_ERROR_INVAL;

    if (IS_ERR((ret = INLINE_SYSCALL(pipe, 1, &fds[0]))) ||
        IS_ERR((ret = INLINE_SYSCALL(pipe, 1, &fds[2]))) ||
        IS_ERR((ret = INLINE_SYSCALL(socketpair, 4, AF_UNIX, SOCK_STREAM,
                                     0, &fds[4])))) {
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    int proc_fds[2][3] = {
        { fds[0], fds[3], fds[4] },
        { fds[2], fds[1], fds[5] },
    };

    const char ** argv = __alloca(sizeof(const char *) * (nargs + 2));
    argv[0] = PAL_LOADER;
    memcpy(argv + 1, args, sizeof(const char *) * nargs);
    argv[nargs + 1] = NULL;

    ret = ARCH_VFORK();

    if (IS_ERR(ret)) {
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    if (!ret) {
        for (int i = 0 ; i < 3 ; i++)
            INLINE_SYSCALL(close, 1, proc_fds[1][i]);

        INLINE_SYSCALL(close, 1, PROC_INIT_FD);
        rete = INLINE_SYSCALL(dup2, 2, proc_fds[0][0], PROC_INIT_FD);
        if (IS_ERR(rete))
            goto out_child;

        rete = INLINE_SYSCALL(execve, 3, PAL_LOADER, argv, NULL);

        /* shouldn't get to here */
        SGX_DBG(DBG_E, "unexpected failure of new process\n");
out_child:
        asm("hlt");
        return 0;
    }

    if (IS_ERR(rete)) {
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    child = ret;

    for (int i = 0 ; i < 3 ; i++)
        INLINE_SYSCALL(close, 1, proc_fds[0][i]);

    int pipe_in = proc_fds[1][0], pipe_out = proc_fds[1][1];

    struct pal_sec * pal_sec = &current_enclave->pal_sec;
    struct proc_args proc_args;
    memcpy(proc_args.exec_name, uri, sizeof(PAL_SEC_STR));
    proc_args.instance_id   = pal_sec->instance_id;
    proc_args.parent_process_id = pal_sec->pid;
    proc_args.proc_fds[0] = proc_fds[0][0];
    proc_args.proc_fds[1] = proc_fds[0][1];
    proc_args.proc_fds[2] = proc_fds[0][2];
    memcpy(proc_args.pipe_prefix, pal_sec->pipe_prefix, sizeof(PAL_SEC_STR));
    proc_args.mcast_port = pal_sec->mcast_port;

    ret = INLINE_SYSCALL(write, 3, pipe_out, &proc_args,
                         sizeof(struct proc_args));

    if (IS_ERR(ret) || ret < sizeof(struct proc_args)) {
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    ret = INLINE_SYSCALL(read, 3, pipe_in, &rete, sizeof(int));

    if (IS_ERR(ret) || ret < sizeof(int)) {
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    if (rete < 0) {
        ret = rete;
        goto out;
    }

    for (int i = 0 ; i < 3 ; i++) {
        INLINE_SYSCALL(fcntl, 3, proc_fds[1][i], F_SETFD, FD_CLOEXEC);
        retfds[i] = proc_fds[1][i];
    }

    ret = child;
out:
    if (ret < 0) {
        for (int i = 0 ; i < 6 ; i++)
            if (fds[i] >= 0)
                INLINE_SYSCALL(close, 1, fds[i]);
    }

    return ret;
}

int sgx_init_child_process (struct pal_sec * pal_sec)
{
    struct proc_args proc_args;

    int ret = INLINE_SYSCALL(read, 3, PROC_INIT_FD, &proc_args,
                             sizeof(struct proc_args));

    if (IS_ERR(ret) && ERRNO(ret) == EBADF)
        return 0;

    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    int child_status = 0;
    ret = INLINE_SYSCALL(write, 3, proc_args.proc_fds[1], &child_status,
                         sizeof(int));
    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    memcpy(pal_sec->exec_name, proc_args.exec_name, sizeof(PAL_SEC_STR));
    pal_sec->instance_id   = proc_args.instance_id;
    pal_sec->ppid        = proc_args.parent_process_id;
    pal_sec->proc_fds[0] = proc_args.proc_fds[0];
    pal_sec->proc_fds[1] = proc_args.proc_fds[1];
    pal_sec->proc_fds[2] = proc_args.proc_fds[2];
    memcpy(pal_sec->pipe_prefix, proc_args.pipe_prefix, sizeof(PAL_SEC_STR));
    pal_sec->mcast_port  = proc_args.mcast_port;

    return 1;
}
