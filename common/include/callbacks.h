/*
 * Defines a set of callbacks that the common library expects from environment it is linked into.
 * Currently, the common library expects `shim_`-prefixed callbacks from LibOS, `pal_`-prefixed
 * callbacks from PAL, and not-prefixed callbacks from all other environments (e.g., PAL regression
 * tests and non-Graphene programs). This header aliases the actual callback implementations, i.e.,
 * `shim_abort()` is aliased as `abort()` for use by the common library.
 *
 * Strictly speaking, current Graphene doesn't need different callback names for LibOS, PAL and
 * other environments. We introduce this notation for the future change where LibOS and PAL will be
 * statically linked together in a single binary (thus, we want to avoid name collisions in
 * callbacks).
 *
 * All environments should implement the following callbacks:
 *
 * - log_always(), prints a non-optional debug message
 * - abort(), terminates the process
 *
 */

#ifndef COMMON_CALLBACKS_H
#define COMMON_CALLBACKS_H

#include <stdnoreturn.h>

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

#endif /* COMMON_CALLBACKS_H */
