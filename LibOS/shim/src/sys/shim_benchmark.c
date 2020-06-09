/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * shim_benchmark.c
 *
 * Implementation of system call "benchmark_ipc", "send_rpc" and "recv_rpc".
 * (These system calls are added for benchmarking purpose.)
 */

#include <errno.h>
#include <shim_internal.h>
#include <shim_ipc.h>
#include <shim_table.h>
#include <shim_unistd.h>

int get_pid_port(IDTYPE pid, IDTYPE* dest, struct shim_ipc_port** port);

int shim_do_benchmark_rpc(pid_t pid, int times, const void* buf, size_t size) {
    int ret = 0;
    IDTYPE dest;
    struct shim_ipc_port* port = NULL;

    if ((ret = get_pid_port(pid, &dest, &port)) < 0)
        return ret;

    ret = ipc_pid_nop_send(port, dest, times, buf, size);
    put_ipc_port(port);
    return ret;
}

size_t shim_do_send_rpc(pid_t pid, const void* buf, size_t size) {
    return ipc_pid_sendrpc_send(pid, get_cur_tid(), buf, size);
}

int get_rpc_msg(IDTYPE* sender, void* buf, int len);

size_t shim_do_recv_rpc(pid_t* pid, void* buf, size_t size) {
    IDTYPE sender;
    int ret = get_rpc_msg(&sender, buf, size);
    if (ret < 0)
        return ret;
    if (pid)
        *pid = sender;
    return ret;
}
