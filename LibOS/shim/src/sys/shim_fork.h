#ifndef _SHIM_FORK_H_
#define _SHIM_FORK_H_

#include <stdarg.h>

#include <shim_checkpoint.h>

int migrate_fork(struct shim_cp_store* store, struct shim_thread* thread,
                 struct shim_process* process, va_list ap);

#endif /* _SHIM_FORK_H_ */
