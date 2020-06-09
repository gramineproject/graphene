/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef _SHIM_IPC_PID_H_
#define _SHIM_IPC_PID_H_

#include <shim_ipc.h>

int init_ipc_ports(void);
int init_ns_pid(void);
int init_ns_sysv(void);

void debug_print_pid_ranges(void);

int get_pid_port(IDTYPE pid, IDTYPE* dest, struct shim_ipc_port** port);
int get_rpc_msg(IDTYPE* sender, void* buf, int len);
int get_all_pid_status(struct pid_status** status);

#endif /* _SHIM_IPC_PID_H_ */
