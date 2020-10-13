/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef _SHIM_FORK_H_
#define _SHIM_FORK_H_

#include <stdarg.h>

#include "shim_checkpoint.h"

int migrate_fork(struct shim_cp_store* store, struct shim_thread* thread,
                 struct shim_process_ipc_info* process, va_list ap);

#endif /* _SHIM_FORK_H_ */
