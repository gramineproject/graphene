#ifndef _SHIM_TYPES_ARCH_H_
#define _SHIM_TYPES_ARCH_H_

#include <stdint.h>

#include "shim_tcb-arch.h"

/* asm/signal.h */
#define NUM_SIGS 64
#define SIGRTMIN 32

typedef struct {
    unsigned long __val[NUM_SIGS / (8 * sizeof(unsigned long))];
} __sigset_t;

#define RED_ZONE_SIZE 128

#endif /* _SHIM_TYPES_ARCH_H_ */
