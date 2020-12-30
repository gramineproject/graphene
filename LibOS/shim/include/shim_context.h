/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * This file contains definitions for CPU context.
 */

#ifndef _SHIM_CONTEXT_H_
#define _SHIM_CONTEXT_H_

extern bool     g_shim_xsave_enabled;
extern uint64_t g_shim_xsave_features;
extern uint32_t g_shim_xsave_size;

void shim_xstate_init(void);
uint64_t shim_xstate_size(void);
void shim_xstate_save(void* xstate_extended);
void shim_xstate_restore(const void* xstate_extended);
void shim_xstate_reset(void);

#endif /* _SHIM_CONTEXT_H_ */
