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
 * shim_benchmark.c
 *
 * Implementation of system call "benchmark_ipc", "send_rpc" and "recv_rpc".
 * (These system calls are added for benchmarking purpose.)
 */

#include <errno.h>
#include <shim_internal.h>
#include <shim_ipc.h>
#include <shim_profile.h>
#include <shim_table.h>
#include <shim_unistd.h>

int get_pid_port(IDTYPE pid, IDTYPE* dest, struct shim_ipc_port** port);

int shim_do_benchmark_rpc(pid_t pid, int times, const void* buf, size_t size) {
    INC_PROFILE_OCCURENCE(syscall_use_ipc);
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
