/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * shim_context.h
 *
 * This file contains definitions for CPU context.
 */

#ifndef _SHIM_CONTEXT_H_
#define _SHIM_CONTEXT_H_

#include "shim_tcb.h"

extern bool     g_shim_xsave_enabled;
extern uint64_t g_shim_xsave_features;
extern uint32_t g_shim_xsave_size;

void shim_xsave_init(void);
void shim_xsave_save(struct shim_xregs_state* xregs_state);
void shim_xsave_restore(const struct shim_xregs_state* xregs_state);
void shim_xsave_reset(void);

void restore_context(struct shim_context* context);
void fixup_child_context(struct shim_regs* regs);

#endif /* _SHIM_CONTEXT_H_ */
