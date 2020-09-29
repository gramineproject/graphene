/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * This file contains definitions for CPU context.
 */

#ifndef _SHIM_CONTEXT_H_
#define _SHIM_CONTEXT_H_

#include <stdnoreturn.h>

#include "shim_tcb.h"

extern bool     g_shim_xsave_enabled;
extern uint64_t g_shim_xsave_features;
extern uint32_t g_shim_xsave_size;

void shim_xstate_init(void);
void shim_xstate_save(void* xstate_extended);
void shim_xstate_restore(const void* xstate_extended);
void shim_xstate_reset(void);

noreturn void restore_child_context_after_clone(struct shim_context* context);
void fixup_child_context(struct shim_regs* regs);

#endif /* _SHIM_CONTEXT_H_ */
