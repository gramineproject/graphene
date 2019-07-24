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

#define COMPILE_TIME_ASSERT(pred) switch(0){case 0:case (pred):;}

/* All environments should implement warn, which prints a non-optional debug
 * message. All environments should also implement __abort, which
 * terminates the process.
 */

void warn (const char *format, ...) __attribute__((format(printf, 1, 2)));
noreturn void __abort(void);

# define assert(test)                                                   \
    ({                                                                  \
        long _val = (long)(test);                                       \
        (!(_val))                                                       \
            ? ({                                                        \
                    warn("assert failed " __FILE__ ":%d %s (value:%lx)\n", \
                         __LINE__, #test, _val);                        \
                    __abort(); })                                       \
            : (void)0;                                                  \
    })

#endif
