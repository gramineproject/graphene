/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/*
 * assert.h
 *
 * Define a common interface for assertions that builds for both the PAL
 * and libOS.
 *
 */

#ifndef ASSERT_H
#define ASSERT_H

#define COMPILE_TIME_ASSERT(pred) switch(0){case 0:case pred:;}

/* All environments should implement warn, which prints a non-optional debug
 * message. All environments should also implement __abort, which
 * terminates the process.
 */

void warn (const char *format, ...);
void __abort(void);

# define assert(test)                                                   \
    ({                                                                  \
        long _val = (long) (test);                                      \
        (!(_val))                                                       \
            ? ({                                                        \
                    warn("assert failed " __FILE__ ":%d " #test " (value:%x)\n", \
                         __LINE__, _val);                               \
                    __abort(); })                                       \
            : (void) 0;                                                 \
    })

#endif
