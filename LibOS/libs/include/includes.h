#ifndef __LIBOS_LIBS_INCLUDES_H__
#define __LIBOS_LIBS_INCLUDES_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <api.h>
#include <pal/pal.h>
#include <pal/pal_debug.h>

static inline size_t aligndown(size_t m) {
    return m & ~(pal_control.alloc_align - 1);
}

static inline size_t alignup(size_t m) {
    return aligndown(m + pal_control.alloc_align - 1);
}
#endif
