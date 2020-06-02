/*
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
