/*
 * assert.h
 *
 * Define a common interface for assertions that builds for both the PAL
 * and libOS.
 *
 */

#ifndef ASSERT_H
#define ASSERT_H

#include <stdnoreturn.h>

#define static_assert _Static_assert

/* All environments should implement warn, which prints a non-optional debug
 * message. All environments should also implement __abort, which
 * terminates the process.
 */

void warn(const char* format, ...) __attribute__((format(printf, 1, 2)));
noreturn void __abort(void);

/* TODO(mkow): We should actually use the standard `NDEBUG`, but that would require changes in the
 * build system.
 */
#ifdef DEBUG
#define assert(expr)                                                     \
    ({                                                                   \
        (!(expr)) ? ({                                                   \
            warn("assert failed " __FILE__ ":%d %s\n", __LINE__, #expr); \
            __abort();                                                   \
        })                                                               \
                  : (void)0;                                             \
    })
#else
#define assert(expr) ((void)0)
#endif

#endif  /* ASSERT_H */
