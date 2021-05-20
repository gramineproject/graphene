/*
 * Define a common interface for assertions that builds for both the PAL and libOS.
 */

#ifndef ASSERT_H
#define ASSERT_H

#include <stdnoreturn.h>

#include "callbacks.h"

noreturn void __stack_chk_fail(void);

#define static_assert _Static_assert

/* TODO(mkow): We should actually use the standard `NDEBUG`, but that would require changes in the
 * build system.
 */
#ifdef DEBUG
/* This `if` is weird intentionally - not to have parentheses around `expr` to catch `assert(x = y)`
 * errors. */
#define assert(expr)                                                              \
    ({                                                                            \
        if (expr) {} else {                                                       \
            log_always("assert failed " __FILE__ ":%d %s\n", __LINE__, #expr);    \
            abort();                                                              \
        }                                                                         \
        (void)0;                                                                  \
    })
#else
#define assert(expr) ((void)0)
#endif

#endif /* ASSERT_H */
