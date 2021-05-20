/*
 * Define a common interface for assertions that builds for both the PAL and libOS.
 */

#ifndef ASSERT_H
#define ASSERT_H

#include <stdnoreturn.h>

/* All environments should implement log_always(), which prints a non-optional debug message. All
 * environments should also implement abort(), which terminates the process. This file knows about
 * two such environments, LibOS (shim) and PAL, and aliases their implementations (we do this to
 * avoid clashes between LibOS and PAL symbols). */
#ifdef IN_SHIM
void shim_log_always(const char* format, ...) __attribute__((format(printf, 1, 2)));
noreturn void shim_abort(void);
#define log_always(format...) shim_log_always(format)
#define abort() shim_abort()

#elif IN_PAL
void pal_log_always(const char* format, ...) __attribute__((format(printf, 1, 2)));
noreturn void pal_abort(void);
#define log_always(format...) pal_log_always(format)
#define abort() pal_abort()

#else
void log_always(const char* format, ...) __attribute__((format(printf, 1, 2)));
noreturn void abort(void);
#endif

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
